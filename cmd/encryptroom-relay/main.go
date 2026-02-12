package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fyroc/encryptroom/internal/protocol"
	"golang.org/x/crypto/acme/autocert"
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
	tlsCertFile := flag.String("tls-cert-file", "", "TLS certificate file path (PEM)")
	tlsKeyFile := flag.String("tls-key-file", "", "TLS private key file path (PEM)")
	tlsAutocertDomains := flag.String("tls-autocert-domains", "", "comma-separated domains for Let's Encrypt autocert")
	tlsAutocertEmail := flag.String("tls-autocert-email", "", "email for Let's Encrypt registration (optional)")
	tlsAutocertCache := flag.String("tls-autocert-cache", "autocert-cache", "directory for Let's Encrypt cert cache")
	tlsAutocertHTTPAddr := flag.String("tls-autocert-http-addr", ":80", "HTTP listener for Let's Encrypt HTTP-01 challenge")
	flag.Parse()

	ln, transport, err := newRelayListener(
		*listenAddr,
		*tlsCertFile,
		*tlsKeyFile,
		*tlsAutocertDomains,
		*tlsAutocertEmail,
		*tlsAutocertCache,
		*tlsAutocertHTTPAddr,
	)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	relay := &relayServer{rooms: make(map[string]*roomState)}

	log.Printf("encryptroom-relay listening on %s (%s)", *listenAddr, transport)
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go relay.handleConn(conn)
	}
}

func newRelayListener(
	listenAddr string,
	tlsCertFile string,
	tlsKeyFile string,
	tlsAutocertDomains string,
	tlsAutocertEmail string,
	tlsAutocertCache string,
	tlsAutocertHTTPAddr string,
) (net.Listener, string, error) {
	domains := splitCSV(tlsAutocertDomains)
	certConfigured := tlsCertFile != "" || tlsKeyFile != ""
	autocertConfigured := len(domains) > 0

	if certConfigured && autocertConfigured {
		return nil, "", errors.New("choose either cert/key TLS or tls-autocert-domains, not both")
	}

	if certConfigured {
		if tlsCertFile == "" || tlsKeyFile == "" {
			return nil, "", errors.New("both -tls-cert-file and -tls-key-file are required")
		}
		cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
		if err != nil {
			return nil, "", err
		}
		cfg := &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
		}
		ln, err := tls.Listen("tcp", listenAddr, cfg)
		if err != nil {
			return nil, "", err
		}
		return ln, "tls(cert)", nil
	}

	if autocertConfigured {
		manager := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Email:      strings.TrimSpace(tlsAutocertEmail),
			Cache:      autocert.DirCache(strings.TrimSpace(tlsAutocertCache)),
			HostPolicy: autocert.HostWhitelist(domains...),
		}

		httpAddr := strings.TrimSpace(tlsAutocertHTTPAddr)
		if httpAddr != "" {
			httpSrv := &http.Server{
				Addr:              httpAddr,
				Handler:           manager.HTTPHandler(nil),
				ReadHeaderTimeout: 5 * time.Second,
			}
			go func() {
				if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Printf("autocert HTTP challenge server stopped: %v", err)
				}
			}()
			log.Printf("autocert HTTP-01 challenge listener on %s", httpAddr)
		}

		cfg := manager.TLSConfig()
		cfg.MinVersion = tls.VersionTLS13
		ln, err := tls.Listen("tcp", listenAddr, cfg)
		if err != nil {
			return nil, "", err
		}
		return ln, "tls(autocert)", nil
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, "", err
	}
	return ln, "tcp", nil
}

func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
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
		expectedRoomID := protocol.DeriveRoomIDFromVerifier(*authVerifier)
		if hello.RoomID != expectedRoomID {
			_ = writeAuthError(conn, "room id mismatch")
			return hello.RoomID, verifier, errors.New("room id mismatch")
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
