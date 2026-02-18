package main

import (
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/softwareforprogress/encryptroom/internal/protocol"
)

func TestAuthenticateSuccess(t *testing.T) {
	relay := &relayServer{rooms: make(map[string]*roomState)}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	verifier := testVerifier()
	roomID := protocol.DeriveRoomIDFromVerifier(verifier)

	type result struct {
		roomID   string
		verifier [32]byte
		err      error
	}
	resultCh := make(chan result, 1)
	go func() {
		id, v, err := relay.authenticate(serverConn)
		resultCh <- result{roomID: id, verifier: v, err: err}
		_ = serverConn.Close()
	}()

	performAuth(t, clientConn, roomID, verifier, true)

	select {
	case got := <-resultCh:
		if got.err != nil {
			t.Fatalf("authenticate err: %v", got.err)
		}
		if got.roomID != roomID {
			t.Fatalf("room id mismatch: got %q want %q", got.roomID, roomID)
		}
		if got.verifier != verifier {
			t.Fatal("verifier mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for authenticate result")
	}
}

func TestAuthenticateRejectsBadResponse(t *testing.T) {
	relay := &relayServer{rooms: make(map[string]*roomState)}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	verifier := testVerifier()
	roomID := protocol.DeriveRoomIDFromVerifier(verifier)

	errCh := make(chan error, 1)
	go func() {
		_, _, err := relay.authenticate(serverConn)
		errCh <- err
		_ = serverConn.Close()
	}()

	if err := clientConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	defer clientConn.SetDeadline(time.Time{})

	helloBytes, err := json.Marshal(protocol.HelloPayload{Proto: protocol.ProtocolVersion, RoomID: roomID})
	if err != nil {
		t.Fatalf("marshal hello: %v", err)
	}
	if err := protocol.WriteFrame(clientConn, protocol.FrameTypeHello, helloBytes); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	frameType, challengePayload, err := protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if frameType != protocol.FrameTypeChallenge {
		t.Fatalf("unexpected challenge frame type: %d", frameType)
	}
	challenge, requireVerifier, err := protocol.DecodeChallenge(challengePayload)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if !requireVerifier {
		t.Fatal("expected verifier to be required for new room")
	}

	bad := [32]byte{}
	bad[0] = 1
	authPayload := protocol.EncodeAuthResponse(bad, &verifier)
	if err := protocol.WriteFrame(clientConn, protocol.FrameTypeAuth, authPayload); err != nil {
		t.Fatalf("write bad auth: %v", err)
	}

	frameType, payload, err := protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("read auth error: %v", err)
	}
	if frameType != protocol.FrameTypeAuthError {
		t.Fatalf("expected auth error, got %d", frameType)
	}
	if string(payload) == "" {
		t.Fatal("expected auth error payload")
	}

	_ = challenge // prevent accidental optimizer removal in future edits
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected authenticate error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for authenticate error")
	}
}

func TestRelayForwardsOpaqueCiphertextAndDropsInvalidFrameType(t *testing.T) {
	relay := &relayServer{rooms: make(map[string]*roomState)}
	verifier := testVerifier()
	roomID := protocol.DeriveRoomIDFromVerifier(verifier)

	serverA, clientA := net.Pipe()
	serverB, clientB := net.Pipe()
	defer clientA.Close()
	defer clientB.Close()

	go relay.handleConn(serverA)
	go relay.handleConn(serverB)

	performAuth(t, clientA, roomID, verifier, true)
	waitForRoomVerifier(t, relay, roomID, 2*time.Second)
	performAuth(t, clientB, roomID, verifier, false)

	opaque := []byte{0x00, 0xff, 0x10, 0x20, 0x30, 0x40}
	if err := protocol.WriteFrame(clientA, protocol.FrameTypeCiphertext, opaque); err != nil {
		t.Fatalf("write opaque frame: %v", err)
	}

	if err := clientB.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline B: %v", err)
	}
	defer clientB.SetDeadline(time.Time{})

	frameType, forwarded, err := protocol.ReadFrame(clientB)
	if err != nil {
		t.Fatalf("read forwarded frame: %v", err)
	}
	if frameType != protocol.FrameTypeCiphertext {
		t.Fatalf("expected ciphertext frame, got %d", frameType)
	}
	if string(forwarded) != string(opaque) {
		t.Fatalf("forwarded payload changed: got %x want %x", forwarded, opaque)
	}

	if err := clientA.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline A: %v", err)
	}
	defer clientA.SetDeadline(time.Time{})

	if err := protocol.WriteFrame(clientA, protocol.FrameTypeHello, nil); err != nil {
		t.Fatalf("write invalid frame type: %v", err)
	}

	_, _, err = protocol.ReadFrame(clientA)
	if err == nil {
		t.Fatal("expected connection close after invalid frame type")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("expected close, got timeout: %v", err)
	}
}

func performAuth(t *testing.T, conn net.Conn, roomID string, verifier [32]byte, sendVerifierOnAuth bool) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	defer conn.SetDeadline(time.Time{})

	hello := protocol.HelloPayload{Proto: protocol.ProtocolVersion, RoomID: roomID}
	helloBytes, err := json.Marshal(hello)
	if err != nil {
		t.Fatalf("marshal hello: %v", err)
	}
	if err := protocol.WriteFrame(conn, protocol.FrameTypeHello, helloBytes); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	frameType, payload, err := protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if frameType == protocol.FrameTypeAuthError {
		t.Fatalf("unexpected auth error: %s", string(payload))
	}
	if frameType != protocol.FrameTypeChallenge {
		t.Fatalf("unexpected challenge frame: type=%d", frameType)
	}
	challenge, requireVerifier, err := protocol.DecodeChallenge(payload)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}

	response := protocol.ComputeChallengeResponse(verifier, challenge)
	var authPayload []byte
	if requireVerifier {
		if !sendVerifierOnAuth {
			t.Fatal("relay required verifier but test disabled it")
		}
		authPayload = protocol.EncodeAuthResponse(response, &verifier)
	} else {
		authPayload = protocol.EncodeAuthResponse(response, nil)
	}
	if err := protocol.WriteFrame(conn, protocol.FrameTypeAuth, authPayload); err != nil {
		t.Fatalf("write auth response: %v", err)
	}

	frameType, payload, err = protocol.ReadFrame(conn)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	if frameType == protocol.FrameTypeAuthError {
		t.Fatalf("auth error: %s", string(payload))
	}
	if frameType != protocol.FrameTypeAuthOK {
		t.Fatalf("expected auth ok frame, got %d", frameType)
	}
}

func testVerifier() [32]byte {
	secret := [32]byte{}
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	return protocol.DeriveRoomAuthVerifier(secret)
}

func waitForRoomVerifier(t *testing.T, relay *relayServer, roomID string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, ok := relay.getRoomVerifier(roomID); ok {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("room verifier not registered in time for room %q", roomID)
}

func TestAuthenticateRejectsRoomIDVerifierMismatch(t *testing.T) {
	relay := &relayServer{rooms: make(map[string]*roomState)}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	verifier := testVerifier()
	roomID := "not-derived-from-verifier"

	errCh := make(chan error, 1)
	go func() {
		_, _, err := relay.authenticate(serverConn)
		errCh <- err
		_ = serverConn.Close()
	}()

	if err := clientConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	defer clientConn.SetDeadline(time.Time{})

	helloBytes, err := json.Marshal(protocol.HelloPayload{Proto: protocol.ProtocolVersion, RoomID: roomID})
	if err != nil {
		t.Fatalf("marshal hello: %v", err)
	}
	if err := protocol.WriteFrame(clientConn, protocol.FrameTypeHello, helloBytes); err != nil {
		t.Fatalf("write hello: %v", err)
	}

	frameType, challengePayload, err := protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if frameType != protocol.FrameTypeChallenge {
		t.Fatalf("unexpected challenge frame type: %d", frameType)
	}
	challenge, requireVerifier, err := protocol.DecodeChallenge(challengePayload)
	if err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if !requireVerifier {
		t.Fatal("expected verifier to be required for new room")
	}

	response := protocol.ComputeChallengeResponse(verifier, challenge)
	authPayload := protocol.EncodeAuthResponse(response, &verifier)
	if err := protocol.WriteFrame(clientConn, protocol.FrameTypeAuth, authPayload); err != nil {
		t.Fatalf("write auth: %v", err)
	}

	frameType, payload, err := protocol.ReadFrame(clientConn)
	if err != nil {
		t.Fatalf("read auth result: %v", err)
	}
	if frameType != protocol.FrameTypeAuthError {
		t.Fatalf("expected auth error, got %d", frameType)
	}
	if string(payload) == "" {
		t.Fatal("expected auth error payload")
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected authenticate error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for authenticate error")
	}
}

func TestNewRelayListenerRejectsConflictingTLSModes(t *testing.T) {
	_, _, err := newRelayListener(
		":0",
		"cert.pem",
		"key.pem",
		"chat.example.com",
		"",
		"autocert-cache",
		":80",
	)
	if err == nil {
		t.Fatal("expected conflict error when both cert/key and autocert are configured")
	}
}

func TestNewRelayListenerRejectsPartialCertConfig(t *testing.T) {
	_, _, err := newRelayListener(
		":0",
		"cert.pem",
		"",
		"",
		"",
		"autocert-cache",
		":80",
	)
	if err == nil {
		t.Fatal("expected error for partial cert/key TLS config")
	}
}
