package invite

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	roomcrypto "github.com/fyroc/encryptroom/internal/crypto"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Magic           = "ERINV1\x00"
	FooterVersion   = uint32(1)
	PayloadVersion  = byte(1)
	CryptoSuiteIDV1 = "X25519+HKDF-SHA256+ChaCha20-Poly1305-v1"

	saltSize             = 16
	nonceSize            = chacha20poly1305.NonceSize
	passwordSaltSize     = 16
	passwordVerifierSize = 32
)

var (
	ErrInviteNotFound       = errors.New("invite footer not found")
	ErrInviteInvalidFormat  = errors.New("invalid invite footer format")
	ErrInviteInvalidPayload = errors.New("invalid invite payload")
)

// Config is the room configuration carried by an invite.
type Config struct {
	RelayURL         string
	RoomID           string
	RoomName         string
	RoomSecret       [roomcrypto.RoomSecretSize]byte
	CryptoSuiteID    string
	PasswordRequired bool
	PasswordSalt     [passwordSaltSize]byte
	PasswordVerifier [passwordVerifierSize]byte
}

type payloadPlaintext struct {
	RelayURL         string `json:"relay_url"`
	RoomID           string `json:"room_id"`
	RoomName         string `json:"room_name,omitempty"`
	CryptoSuiteID    string `json:"crypto_suite_id"`
	PasswordRequired bool   `json:"password_required,omitempty"`
	PasswordSalt     string `json:"password_salt,omitempty"`
	PasswordVerifier string `json:"password_verifier,omitempty"`
}

func GenerateRoomSecret() ([roomcrypto.RoomSecretSize]byte, error) {
	var secret [roomcrypto.RoomSecretSize]byte
	_, err := rand.Read(secret[:])
	return secret, err
}

func GeneratePasswordVerifier(password string) ([passwordSaltSize]byte, [passwordVerifierSize]byte, error) {
	if password == "" {
		return [passwordSaltSize]byte{}, [passwordVerifierSize]byte{}, errors.New("password cannot be empty")
	}

	var salt [passwordSaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return [passwordSaltSize]byte{}, [passwordVerifierSize]byte{}, err
	}
	verifier, err := derivePasswordVerifier(password, salt)
	if err != nil {
		return [passwordSaltSize]byte{}, [passwordVerifierSize]byte{}, err
	}
	return salt, verifier, nil
}

func (c Config) RequiresPassword() bool {
	return c.PasswordRequired
}

func (c Config) VerifyPassword(password string) bool {
	if !c.PasswordRequired {
		return true
	}
	derived, err := derivePasswordVerifier(password, c.PasswordSalt)
	if err != nil {
		return false
	}
	return hmac.Equal(derived[:], c.PasswordVerifier[:])
}

func MarshalFooter(cfg Config) ([]byte, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}

	payload, err := marshalPayload(normalized)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, len(Magic)+8+len(payload))
	out = append(out, []byte(Magic)...)

	var header [8]byte
	binary.BigEndian.PutUint32(header[0:4], FooterVersion)
	binary.BigEndian.PutUint32(header[4:8], uint32(len(payload)))
	out = append(out, header[:]...)
	out = append(out, payload...)
	return out, nil
}

func ParseFooter(data []byte) (Config, error) {
	idx := bytes.LastIndex(data, []byte(Magic))
	if idx < 0 {
		return Config{}, ErrInviteNotFound
	}
	if idx+len(Magic)+8 > len(data) {
		return Config{}, ErrInviteInvalidFormat
	}

	version := binary.BigEndian.Uint32(data[idx+len(Magic) : idx+len(Magic)+4])
	if version != FooterVersion {
		return Config{}, fmt.Errorf("%w: unsupported footer version %d", ErrInviteInvalidFormat, version)
	}

	payloadLen := int(binary.BigEndian.Uint32(data[idx+len(Magic)+4 : idx+len(Magic)+8]))
	payloadStart := idx + len(Magic) + 8
	payloadEnd := payloadStart + payloadLen
	if payloadLen <= 0 || payloadEnd != len(data) {
		return Config{}, ErrInviteInvalidFormat
	}

	cfg, err := parsePayload(data[payloadStart:payloadEnd])
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func ReadInviteFromSelf() (Config, error) {
	exe, err := os.Executable()
	if err != nil {
		return Config{}, err
	}
	b, err := os.ReadFile(exe)
	if err != nil {
		return Config{}, err
	}
	return ParseFooter(b)
}

func ReadInviteFromFile(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg, footerErr := ParseFooter(b)
	if footerErr == nil {
		return cfg, nil
	}
	if errors.Is(footerErr, ErrInviteNotFound) {
		return parsePayload(b)
	}
	return Config{}, footerErr
}

func WriteInviteToFile(path string, cfg Config) error {
	footer, err := MarshalFooter(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, footer, 0o600)
}

func WriteInviteToBinary(binaryPath, outputPath string, cfg Config) error {
	bin, err := os.ReadFile(binaryPath)
	if err != nil {
		return err
	}
	footer, err := MarshalFooter(cfg)
	if err != nil {
		return err
	}
	out := make([]byte, 0, len(bin)+len(footer))
	out = append(out, bin...)
	out = append(out, footer...)
	return os.WriteFile(outputPath, out, 0o755)
}

// readInviteFromSelf exists to match the requested package API while keeping exported helpers.
func readInviteFromSelf() (Config, error) {
	return ReadInviteFromSelf()
}

// writeInviteToFile exists to match the requested package API while keeping exported helpers.
func writeInviteToFile(path string, cfg Config) error {
	return WriteInviteToFile(path, cfg)
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.RoomName = strings.TrimSpace(cfg.RoomName)

	if cfg.RelayURL == "" {
		return Config{}, fmt.Errorf("%w: relay_url is required", ErrInviteInvalidPayload)
	}
	if _, err := url.ParseRequestURI(cfg.RelayURL); err != nil {
		return Config{}, fmt.Errorf("%w: invalid relay_url", ErrInviteInvalidPayload)
	}

	derivedRoomID, err := roomcrypto.DeriveRoomID(cfg.RoomSecret[:])
	if err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrInviteInvalidPayload, err)
	}
	if cfg.RoomID == "" {
		cfg.RoomID = derivedRoomID
	}
	if cfg.RoomID != derivedRoomID {
		return Config{}, fmt.Errorf("%w: room_id does not match room_secret", ErrInviteInvalidPayload)
	}
	if cfg.CryptoSuiteID == "" {
		cfg.CryptoSuiteID = CryptoSuiteIDV1
	}
	if cfg.CryptoSuiteID != CryptoSuiteIDV1 {
		return Config{}, fmt.Errorf("%w: unsupported crypto suite", ErrInviteInvalidPayload)
	}
	if !cfg.PasswordRequired {
		cfg.PasswordSalt = [passwordSaltSize]byte{}
		cfg.PasswordVerifier = [passwordVerifierSize]byte{}
	}
	return cfg, nil
}

func marshalPayload(cfg Config) ([]byte, error) {
	plain := payloadPlaintext{
		RelayURL:      cfg.RelayURL,
		RoomID:        cfg.RoomID,
		RoomName:      cfg.RoomName,
		CryptoSuiteID: cfg.CryptoSuiteID,
	}
	if cfg.PasswordRequired {
		plain.PasswordRequired = true
		plain.PasswordSalt = base64.StdEncoding.EncodeToString(cfg.PasswordSalt[:])
		plain.PasswordVerifier = base64.StdEncoding.EncodeToString(cfg.PasswordVerifier[:])
	}
	plainBytes, err := json.Marshal(plain)
	if err != nil {
		return nil, err
	}

	var salt [saltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	key, err := deriveInviteKey(cfg.RoomSecret[:], salt[:])
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	aad := buildAAD(cfg.RoomSecret[:], salt[:], nonce[:])
	ciphertext := aead.Seal(nil, nonce[:], plainBytes, aad)

	out := make([]byte, 0, 1+roomcrypto.RoomSecretSize+saltSize+nonceSize+len(ciphertext))
	out = append(out, PayloadVersion)
	out = append(out, cfg.RoomSecret[:]...)
	out = append(out, salt[:]...)
	out = append(out, nonce[:]...)
	out = append(out, ciphertext...)
	return out, nil
}

func parsePayload(payload []byte) (Config, error) {
	minLen := 1 + roomcrypto.RoomSecretSize + saltSize + nonceSize + chacha20poly1305.Overhead
	if len(payload) < minLen {
		return Config{}, ErrInviteInvalidPayload
	}
	if payload[0] != PayloadVersion {
		return Config{}, fmt.Errorf("%w: unsupported payload version %d", ErrInviteInvalidPayload, payload[0])
	}

	var secret [roomcrypto.RoomSecretSize]byte
	copy(secret[:], payload[1:1+roomcrypto.RoomSecretSize])
	saltStart := 1 + roomcrypto.RoomSecretSize
	nonceStart := saltStart + saltSize
	cipherStart := nonceStart + nonceSize
	salt := payload[saltStart:nonceStart]
	nonce := payload[nonceStart:cipherStart]
	ciphertext := payload[cipherStart:]

	key, err := deriveInviteKey(secret[:], salt)
	if err != nil {
		return Config{}, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return Config{}, err
	}

	aad := buildAAD(secret[:], salt, nonce)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return Config{}, fmt.Errorf("%w: auth/decrypt failed", ErrInviteInvalidPayload)
	}

	var parsed payloadPlaintext
	if err := json.Unmarshal(plaintext, &parsed); err != nil {
		return Config{}, fmt.Errorf("%w: malformed payload json", ErrInviteInvalidPayload)
	}

	cfg := Config{
		RelayURL:         parsed.RelayURL,
		RoomID:           parsed.RoomID,
		RoomName:         parsed.RoomName,
		RoomSecret:       secret,
		CryptoSuiteID:    parsed.CryptoSuiteID,
		PasswordRequired: parsed.PasswordRequired,
	}
	if parsed.PasswordRequired {
		decodedSalt, err := base64.StdEncoding.DecodeString(parsed.PasswordSalt)
		if err != nil || len(decodedSalt) != passwordSaltSize {
			return Config{}, fmt.Errorf("%w: invalid password_salt", ErrInviteInvalidPayload)
		}
		decodedVerifier, err := base64.StdEncoding.DecodeString(parsed.PasswordVerifier)
		if err != nil || len(decodedVerifier) != passwordVerifierSize {
			return Config{}, fmt.Errorf("%w: invalid password_verifier", ErrInviteInvalidPayload)
		}
		copy(cfg.PasswordSalt[:], decodedSalt)
		copy(cfg.PasswordVerifier[:], decodedVerifier)
	}

	cfg, err = normalizeConfig(cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func deriveInviteKey(roomSecret, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, roomSecret, salt, "encryptroom/invite-key/v1", chacha20poly1305.KeySize)
}

func derivePasswordVerifier(password string, salt [passwordSaltSize]byte) ([passwordVerifierSize]byte, error) {
	verifierBytes, err := hkdf.Key(sha256.New, []byte(password), salt[:], "encryptroom/password-verifier/v1", passwordVerifierSize)
	if err != nil {
		return [passwordVerifierSize]byte{}, err
	}
	var verifier [passwordVerifierSize]byte
	copy(verifier[:], verifierBytes)
	return verifier, nil
}

func buildAAD(roomSecret, salt, nonce []byte) []byte {
	aad := make([]byte, 0, len(roomSecret)+len(salt)+len(nonce)+32)
	aad = append(aad, []byte("encryptroom/invite-envelope/v1")...)
	aad = append(aad, roomSecret...)
	aad = append(aad, salt...)
	aad = append(aad, nonce...)
	return aad
}
