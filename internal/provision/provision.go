package provision

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/fyroc/encryptroom/internal/invite"
)

const (
	maxChatNameLen = 64
	maxPasswordLen = 256
)

var (
	ErrChatNameRequired = errors.New("chat_name is required")
	ErrPasswordRequired = errors.New("password is required")
	ErrRelayURLRequired = errors.New("relay_url is required")
)

type BundleRequest struct {
	ChatName string
	Password string
	RelayURL string
}

func BuildInviteConfig(req BundleRequest, defaultRelayURL string) (invite.Config, string, error) {
	chatName := strings.TrimSpace(req.ChatName)
	if chatName == "" {
		return invite.Config{}, "", ErrChatNameRequired
	}
	if len(chatName) > maxChatNameLen {
		return invite.Config{}, "", fmt.Errorf("chat_name too long (max %d)", maxChatNameLen)
	}
	if req.Password == "" {
		return invite.Config{}, "", ErrPasswordRequired
	}
	if len(req.Password) > maxPasswordLen {
		return invite.Config{}, "", fmt.Errorf("password too long (max %d)", maxPasswordLen)
	}

	relayURL := strings.TrimSpace(req.RelayURL)
	if relayURL == "" {
		relayURL = strings.TrimSpace(defaultRelayURL)
	}
	if relayURL == "" {
		return invite.Config{}, "", ErrRelayURLRequired
	}

	secret, err := deriveRoomSecret(chatName, req.Password)
	if err != nil {
		return invite.Config{}, "", err
	}
	base := invite.Config{
		RelayURL:      relayURL,
		RoomSecret:    secret,
		RoomName:      chatName,
		CryptoSuiteID: invite.CryptoSuiteIDV1,
	}
	cfg, err := invite.ProtectWithPassword(base, req.Password)
	if err != nil {
		return invite.Config{}, "", err
	}

	// Parse what we just marshaled to guarantee normalized fields are populated and valid.
	footer, err := invite.MarshalFooter(cfg)
	if err != nil {
		return invite.Config{}, "", err
	}
	parsed, err := invite.ParseFooter(footer)
	if err != nil {
		return invite.Config{}, "", err
	}
	if _, err := parsed.UnlockWithPassword(req.Password); err != nil {
		return invite.Config{}, "", err
	}
	return cfg, Slug(chatName), nil
}

func deriveRoomSecret(chatName, password string) ([32]byte, error) {
	var randomSeed [32]byte
	if _, err := rand.Read(randomSeed[:]); err != nil {
		return [32]byte{}, err
	}

	namePasswordHash := sha256.Sum256([]byte(chatName + "\x00" + password))
	secretBytes, err := hkdf.Key(sha256.New, randomSeed[:], namePasswordHash[:], "encryptroom/provision/room-secret/v1", 32)
	if err != nil {
		return [32]byte{}, err
	}

	var secret [32]byte
	copy(secret[:], secretBytes)
	return secret, nil
}

func Slug(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "chat"
	}

	var b strings.Builder
	lastDash := false
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}

	slug := strings.Trim(b.String(), "-")
	if slug == "" {
		return "chat"
	}
	if len(slug) > 40 {
		slug = slug[:40]
		slug = strings.Trim(slug, "-")
		if slug == "" {
			return "chat"
		}
	}
	return slug
}
