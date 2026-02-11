package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	roomcrypto "github.com/fyroc/encryptroom/internal/crypto"
	"github.com/fyroc/encryptroom/internal/invite"
	"github.com/fyroc/encryptroom/internal/protocol"
)

var errInputClosed = errors.New("input closed")
var errUserExit = errors.New("user exit")

const (
	messageTypeChat          = "chat"
	messageTypePresenceJoin  = "presence_join"
	messageTypePresenceLeave = "presence_leave"
)

type chatPayload struct {
	Type        string `json:"type,omitempty"`
	DisplayName string `json:"display_name"`
	Body        string `json:"body"`
	SentAtUnix  int64  `json:"sent_at_unix"`
}

func main() {
	invitePath := flag.String("invite-file", "", "path to invite file for development mode")
	nameFlag := flag.String("name", "", "display name")
	relayOverride := flag.String("relay-url", "", "override relay URL from invite")
	reconnectDelay := flag.Duration("reconnect-delay", 3*time.Second, "delay before reconnect")
	flag.Parse()

	cfg, err := loadInvite(*invitePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load invite: %v\n", err)
		os.Exit(1)
	}
	if *relayOverride != "" {
		cfg.RelayURL = *relayOverride
	}

	addr, err := resolveRelayAddress(cfg.RelayURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid relay URL: %v\n", err)
		os.Exit(1)
	}

	displayName := strings.TrimSpace(*nameFlag)
	if displayName == "" {
		displayName, err = promptDisplayName()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read display name: %v\n", err)
			os.Exit(1)
		}
	}
	if cfg.RequiresPassword() {
		if err := promptAndVerifyPassword(cfg); err != nil {
			fmt.Fprintf(os.Stderr, "password verification failed: %v\n", err)
			os.Exit(1)
		}
	}

	lines := make(chan string, 64)
	go scanInput(lines)

	quit := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		<-sigCh
		close(quit)
	}()

	for {
		err := runConnection(addr, cfg, displayName, lines, quit)
		if errors.Is(err, errInputClosed) || errors.Is(err, errUserExit) {
			return
		}
		fmt.Fprintf(os.Stderr, "disconnected (%v), reconnecting in %s...\n", err, reconnectDelay.String())
		time.Sleep(*reconnectDelay)
	}
}

func loadInvite(path string) (invite.Config, error) {
	if path == "" {
		return invite.ReadInviteFromSelf()
	}
	return invite.ReadInviteFromFile(path)
}

func resolveRelayAddress(relayURL string) (string, error) {
	parsed, err := url.Parse(relayURL)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "tcp":
		if parsed.Host == "" {
			return "", errors.New("missing host")
		}
		return parsed.Host, nil
	case "":
		if relayURL == "" {
			return "", errors.New("empty relay address")
		}
		return relayURL, nil
	default:
		return "", fmt.Errorf("unsupported scheme %q (use tcp://)", parsed.Scheme)
	}
}

func promptDisplayName() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Display name: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		name := strings.TrimSpace(line)
		if name != "" {
			return name, nil
		}
	}
}

func promptAndVerifyPassword(cfg invite.Config) error {
	reader := bufio.NewReader(os.Stdin)
	for attempts := 0; attempts < 3; attempts++ {
		fmt.Print("Room password: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		password := strings.TrimRight(line, "\r\n")
		if cfg.VerifyPassword(password) {
			return nil
		}
		fmt.Fprintln(os.Stderr, "invalid room password")
	}
	return errors.New("too many failed attempts")
}

func scanInput(out chan<- string) {
	defer close(out)
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		out <- scanner.Text()
	}
}

func runConnection(addr string, cfg invite.Config, displayName string, lines <-chan string, quit <-chan struct{}) error {
	session, err := roomcrypto.NewSession(cfg.RoomSecret[:])
	if err != nil {
		return err
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if err := authenticate(conn, cfg.RoomID, cfg.RoomSecret); err != nil {
		return err
	}
	roomLabel := cfg.RoomID
	if cfg.RoomName != "" {
		roomLabel = fmt.Sprintf("%s (%s)", cfg.RoomName, cfg.RoomID)
	}
	fmt.Printf("connected to room %s via %s\n", roomLabel, cfg.RelayURL)
	_ = sendPresence(conn, session, displayName, messageTypePresenceJoin)

	readErr := make(chan error, 1)
	go readMessages(conn, session, readErr)

	for {
		select {
		case <-quit:
			_ = sendPresence(conn, session, displayName, messageTypePresenceLeave)
			return errUserExit
		case err := <-readErr:
			return err
		case line, ok := <-lines:
			if !ok {
				_ = sendPresence(conn, session, displayName, messageTypePresenceLeave)
				return errInputClosed
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.EqualFold(line, "/exit") || strings.EqualFold(line, "/quit") {
				_ = sendPresence(conn, session, displayName, messageTypePresenceLeave)
				return errUserExit
			}

			payload := chatPayload{
				Type:        messageTypeChat,
				DisplayName: displayName,
				Body:        line,
				SentAtUnix:  time.Now().Unix(),
			}
			if err := sendPayload(conn, session, payload); err != nil {
				return err
			}
		}
	}
}

func readMessages(conn net.Conn, session *roomcrypto.Session, errs chan<- error) {
	for {
		frameType, payload, err := protocol.ReadFrame(conn)
		if err != nil {
			errs <- err
			return
		}
		if frameType != protocol.FrameTypeCiphertext {
			continue
		}

		plaintext, _, _, err := session.Decrypt(payload)
		if err != nil {
			if errors.Is(err, roomcrypto.ErrReplayDetected) {
				continue
			}
			continue
		}

		var msg chatPayload
		if err := json.Unmarshal(plaintext, &msg); err != nil {
			continue
		}

		ts := time.Unix(msg.SentAtUnix, 0).Format("15:04:05")
		switch msg.Type {
		case messageTypePresenceJoin:
			fmt.Printf("[%s] %s has entered chat\n", ts, msg.DisplayName)
		case messageTypePresenceLeave:
			fmt.Printf("[%s] %s has closed the chat\n", ts, msg.DisplayName)
		default:
			fmt.Printf("[%s] %s: %s\n", ts, msg.DisplayName, msg.Body)
		}
	}
}

func sendPresence(conn net.Conn, session *roomcrypto.Session, displayName, eventType string) error {
	payload := chatPayload{
		Type:        eventType,
		DisplayName: displayName,
		Body:        "",
		SentAtUnix:  time.Now().Unix(),
	}
	return sendPayload(conn, session, payload)
}

func sendPayload(conn net.Conn, session *roomcrypto.Session, payload chatPayload) error {
	plain, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	encrypted, err := session.Encrypt(plain)
	if err != nil {
		return err
	}
	return protocol.WriteFrame(conn, protocol.FrameTypeCiphertext, encrypted)
}

func authenticate(conn net.Conn, roomID string, roomSecret [32]byte) error {
	verifier := protocol.DeriveRoomAuthVerifier(roomSecret)

	hello := protocol.HelloPayload{
		Proto:    protocol.ProtocolVersion,
		RoomID:   roomID,
		RoomAuth: base64.StdEncoding.EncodeToString(verifier[:]),
	}
	helloBytes, err := json.Marshal(hello)
	if err != nil {
		return err
	}
	if err := protocol.WriteFrame(conn, protocol.FrameTypeHello, helloBytes); err != nil {
		return err
	}

	frameType, payload, err := protocol.ReadFrame(conn)
	if err != nil {
		return err
	}
	if frameType == protocol.FrameTypeAuthError {
		return errors.New(string(payload))
	}
	if frameType != protocol.FrameTypeChallenge || len(payload) != 32 {
		return errors.New("relay did not return a valid challenge")
	}

	var challenge [32]byte
	copy(challenge[:], payload)
	response := protocol.ComputeChallengeResponse(verifier, challenge)
	if err := protocol.WriteFrame(conn, protocol.FrameTypeAuth, response[:]); err != nil {
		return err
	}

	frameType, payload, err = protocol.ReadFrame(conn)
	if err != nil {
		return err
	}
	if frameType == protocol.FrameTypeAuthError {
		return errors.New(string(payload))
	}
	if frameType != protocol.FrameTypeAuthOK {
		return errors.New("auth failed")
	}
	return nil
}
