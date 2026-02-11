package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"sync"

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
	roomID, verifier, created, err := r.authenticate(conn)
	if err != nil {
		if created {
			r.cleanupRoomIfUnused(roomID)
		}
		_ = conn.Close()
		return
	}

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

func (r *relayServer) authenticate(conn net.Conn) (string, [32]byte, bool, error) {
	frameType, payload, err := protocol.ReadFrame(conn)
	if err != nil {
		return "", [32]byte{}, false, err
	}
	if frameType != protocol.FrameTypeHello {
		_ = writeAuthError(conn, "expected hello")
		return "", [32]byte{}, false, errors.New("expected hello")
	}

	var hello protocol.HelloPayload
	if err := json.Unmarshal(payload, &hello); err != nil {
		_ = writeAuthError(conn, "invalid hello")
		return "", [32]byte{}, false, errors.New("invalid hello")
	}
	if hello.Proto != protocol.ProtocolVersion || hello.RoomID == "" || hello.RoomAuth == "" {
		_ = writeAuthError(conn, "invalid hello")
		return "", [32]byte{}, false, errors.New("invalid hello")
	}

	decodedVerifier, err := base64.StdEncoding.DecodeString(hello.RoomAuth)
	if err != nil || len(decodedVerifier) != 32 {
		_ = writeAuthError(conn, "invalid verifier")
		return hello.RoomID, [32]byte{}, false, errors.New("invalid verifier")
	}
	var verifier [32]byte
	copy(verifier[:], decodedVerifier)

	created, err := r.ensureRoomVerifier(hello.RoomID, verifier)
	if err != nil {
		_ = writeAuthError(conn, "room auth mismatch")
		return hello.RoomID, verifier, false, err
	}

	challenge, err := protocol.NewChallenge()
	if err != nil {
		_ = writeAuthError(conn, "internal error")
		return hello.RoomID, verifier, created, err
	}
	if err := protocol.WriteFrame(conn, protocol.FrameTypeChallenge, challenge[:]); err != nil {
		return hello.RoomID, verifier, created, err
	}

	frameType, payload, err = protocol.ReadFrame(conn)
	if err != nil {
		return hello.RoomID, verifier, created, err
	}
	if frameType != protocol.FrameTypeAuth || len(payload) != 32 {
		_ = writeAuthError(conn, "invalid auth")
		return hello.RoomID, verifier, created, errors.New("invalid auth")
	}

	var response [32]byte
	copy(response[:], payload)
	if !protocol.VerifyChallengeResponse(verifier, challenge, response) {
		_ = writeAuthError(conn, "auth failed")
		return hello.RoomID, verifier, created, errors.New("auth failed")
	}

	if err := protocol.WriteFrame(conn, protocol.FrameTypeAuthOK, nil); err != nil {
		return hello.RoomID, verifier, created, err
	}
	return hello.RoomID, verifier, created, nil
}

func writeAuthError(w io.Writer, message string) error {
	return protocol.WriteFrame(w, protocol.FrameTypeAuthError, []byte(message))
}

func (r *relayServer) ensureRoomVerifier(roomID string, verifier [32]byte) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	room, ok := r.rooms[roomID]
	if !ok {
		r.rooms[roomID] = &roomState{
			verifier: verifier,
			clients:  make(map[*clientConn]struct{}),
		}
		return true, nil
	}
	if room.verifier != verifier {
		return false, fmt.Errorf("room verifier mismatch")
	}
	return false, nil
}

func (r *relayServer) cleanupRoomIfUnused(roomID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	room, ok := r.rooms[roomID]
	if ok && len(room.clients) == 0 {
		delete(r.rooms, roomID)
	}
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
		frameType, payload, err := protocol.ReadFrame(c.conn)
		if err != nil {
			return
		}
		if frameType != protocol.FrameTypeCiphertext {
			continue
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
