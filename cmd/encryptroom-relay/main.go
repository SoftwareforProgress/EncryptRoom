package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/fyroc/encryptroom/internal/protocol"
)

type roomState struct {
	verifier [32]byte
	clients  map[*clientConn]struct{}
}

type relayServer struct {
	mu    sync.Mutex
	rooms map[string]*roomState
}

type clientConn struct {
	conn   net.Conn
	relay  *relayServer
	roomID string
	send   chan []byte
	closed chan struct{}
	once   sync.Once
}

const (
	handshakeTimeout = 15 * time.Second
	readIdleTimeout  = 5 * time.Minute
	writeTimeout     = 10 * time.Second
)

func main() {
	listenAddr := flag.String("listen", ":8080", "tcp address to listen on")
	flag.Parse()

	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	relay := &relayServer{rooms: make(map[string]*roomState)}

	log.Printf("encryptroom-relay listening on %s", *listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go relay.handleConn(conn)
	}
}

func (r *relayServer) handleConn(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	roomID, verifier, err := r.authenticate(conn)
	if err != nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	c := &clientConn{
		conn:   conn,
		relay:  r,
		roomID: roomID,
		send:   make(chan []byte, 64),
		closed: make(chan struct{}),
	}
	if err := r.register(c, verifier); err != nil {
		c.close()
		return
	}

	go c.writeLoop()
	c.readLoop()
}

func (r *relayServer) authenticate(conn net.Conn) (string, [32]byte, error) {
	frameType, payload, err := protocol.ReadFrame(conn)
	if err != nil {
		return "", [32]byte{}, err
	}
	if frameType != protocol.FrameTypeHello {
		_ = writeAuthError(conn, "expected hello")
		return "", [32]byte{}, errors.New("expected hello")
	}

	var hello protocol.HelloPayload
	if err := json.Unmarshal(payload, &hello); err != nil {
		_ = writeAuthError(conn, "invalid hello")
		return "", [32]byte{}, errors.New("invalid hello")
	}
	if hello.Proto != protocol.ProtocolVersion || hello.RoomID == "" {
		_ = writeAuthError(conn, "invalid hello")
		return "", [32]byte{}, errors.New("invalid hello")
	}

	verifier, exists := r.getRoomVerifier(hello.RoomID)
	requireVerifier := !exists

	challenge, err := protocol.NewChallenge()
	if err != nil {
		_ = writeAuthError(conn, "internal error")
		return hello.RoomID, verifier, err
	}
	challengePayload := protocol.EncodeChallenge(challenge, requireVerifier)
	if err := protocol.WriteFrame(conn, protocol.FrameTypeChallenge, challengePayload); err != nil {
		return hello.RoomID, verifier, err
	}

	frameType, payload, err = protocol.ReadFrame(conn)
	if err != nil {
		return hello.RoomID, verifier, err
	}
	if frameType != protocol.FrameTypeAuth {
		_ = writeAuthError(conn, "invalid auth")
		return hello.RoomID, verifier, errors.New("invalid auth")
	}

	response, authVerifier, err := protocol.DecodeAuthResponse(payload)
	if err != nil {
		_ = writeAuthError(conn, "invalid auth payload")
		return hello.RoomID, verifier, err
	}
	if requireVerifier {
		if authVerifier == nil {
			_ = writeAuthError(conn, "room verifier required")
			return hello.RoomID, verifier, errors.New("missing room verifier")
		}
		verifier = *authVerifier
	} else if authVerifier != nil {
		_ = writeAuthError(conn, "unexpected room verifier")
		return hello.RoomID, verifier, errors.New("unexpected room verifier")
	}

	if !protocol.VerifyChallengeResponse(verifier, challenge, response) {
		_ = writeAuthError(conn, "auth failed")
		return hello.RoomID, verifier, errors.New("auth failed")
	}

	if err := protocol.WriteFrame(conn, protocol.FrameTypeAuthOK, nil); err != nil {
		return hello.RoomID, verifier, err
	}
	return hello.RoomID, verifier, nil
}

func writeAuthError(w io.Writer, message string) error {
	return protocol.WriteFrame(w, protocol.FrameTypeAuthError, []byte(message))
}

func (r *relayServer) getRoomVerifier(roomID string) ([32]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	room, ok := r.rooms[roomID]
	if !ok {
		return [32]byte{}, false
	}
	return room.verifier, true
}

func (r *relayServer) register(c *clientConn, verifier [32]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	room, ok := r.rooms[c.roomID]
	if !ok {
		r.rooms[c.roomID] = &roomState{verifier: verifier, clients: map[*clientConn]struct{}{c: {}}}
		return nil
	}
	if room.verifier != verifier {
		return errors.New("room verifier mismatch")
	}
	room.clients[c] = struct{}{}
	return nil
}

func (r *relayServer) unregister(c *clientConn) {
	r.mu.Lock()
	defer r.mu.Unlock()

	room, ok := r.rooms[c.roomID]
	if !ok {
		return
	}
	delete(room.clients, c)
	if len(room.clients) == 0 {
		delete(r.rooms, c.roomID)
	}
}

func (r *relayServer) broadcast(sender *clientConn, msg []byte) {
	r.mu.Lock()
	room, ok := r.rooms[sender.roomID]
	if !ok {
		r.mu.Unlock()
		return
	}
	targets := make([]*clientConn, 0, len(room.clients))
	for c := range room.clients {
		if c != sender {
			targets = append(targets, c)
		}
	}
	r.mu.Unlock()

	for _, target := range targets {
		select {
		case target.send <- msg:
		default:
			target.close()
		}
	}
}

func (c *clientConn) readLoop() {
	defer c.close()
	for {
		_ = c.conn.SetReadDeadline(time.Now().Add(readIdleTimeout))
		frameType, payload, err := protocol.ReadFrame(c.conn)
		if err != nil {
			return
		}
		if frameType != protocol.FrameTypeCiphertext {
			return
		}
		c.relay.broadcast(c, payload)
	}
}

func (c *clientConn) writeLoop() {
	for {
		select {
		case <-c.closed:
			return
		case msg := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := protocol.WriteFrame(c.conn, protocol.FrameTypeCiphertext, msg); err != nil {
				c.close()
				return
			}
		}
	}
}

func (c *clientConn) close() {
	c.once.Do(func() {
		close(c.closed)
		_ = c.conn.Close()
		c.relay.unregister(c)
	})
}
