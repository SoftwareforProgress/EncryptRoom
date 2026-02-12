package invite

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	roomcrypto "github.com/fyroc/encryptroom/internal/crypto"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	Magic         = "ERINV1\x00"
	FooterVersion = uint32(1)

	payloadVersionLegacy byte = 1
	PayloadVersion       byte = 2

	payloadModeUnprotected     byte = 0
	payloadModePasswordWrapped byte = 1
	CryptoSuiteIDV1                 = "X25519+HKDF-SHA256+ChaCha20-Poly1305-v1"

	legacySaltSize         = 16
	legacyNonceSize        = chacha20poly1305.NonceSize
	passwordSaltSize       = 16
	passwordVerifierSize   = 32
	passwordDerivedKeySize = 32
	passwordWrapNonceSize  = chacha20poly1305.NonceSize
	passwordKDFTime        = 2
	passwordKDFMemoryKiB   = 19 * 1024
	passwordKDFParallelism = 1
)

var (
	ErrInviteNotFound       = errors.New("invite footer not found")
	ErrInviteInvalidFormat  = errors.New("invalid invite footer format")
	ErrInviteInvalidPayload = errors.New("invalid invite payload")
	ErrInviteLocked         = errors.New("invite requires password unlock")
	ErrInvalidPassword      = errors.New("invalid room password")
)

// Config is the room configuration carried by an invite.
type Config struct {
	RelayURL      string
	RoomID        string
	RoomName      string
	RoomSecret    [roomcrypto.RoomSecretSize]byte
	CryptoSuiteID string

	PasswordRequired bool
	PasswordSalt     [passwordSaltSize]byte
	PasswordVerifier [passwordVerifierSize]byte

	passwordWrapNonce      [passwordWrapNonceSize]byte
	passwordWrapCiphertext []byte
}

type payloadPlaintextLegacy struct {
	RelayURL         string `json:"relay_url"`
	RoomID           string `json:"room_id"`
	RoomName         string `json:"room_name,omitempty"`
	CryptoSuiteID    string `json:"crypto_suite_id"`
	PasswordRequired bool   `json:"password_required,omitempty"`
	PasswordSalt     string `json:"password_salt,omitempty"`
	PasswordVerifier string `json:"password_verifier,omitempty"`
}

type protectedPayloadPlaintext struct {
	RelayURL      string `json:"relay_url"`
	RoomID        string `json:"room_id"`
	RoomName      string `json:"room_name,omitempty"`
	RoomSecret    string `json:"room_secret"`
	CryptoSuiteID string `json:"crypto_suite_id"`
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
	verifier, _, err := derivePasswordMaterial(password, salt)
	if err != nil {
		return [passwordSaltSize]byte{}, [passwordVerifierSize]byte{}, err
	}
	return salt, verifier, nil
}

// ProtectWithPassword returns a config that marshals without embedding the room secret in plaintext.
func ProtectWithPassword(cfg Config, password string) (Config, error) {
	normalized, err := normalizeUnlockedConfig(cfg)
	if err != nil {
		return Config{}, err
	}
	if password == "" {
		return Config{}, errors.New("password cannot be empty")
	}

	var salt [passwordSaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return Config{}, err
	}
	verifier, wrapKey, err := derivePasswordMaterial(password, salt)
	if err != nil {
		return Config{}, err
	}

	plain := protectedPayloadPlaintext{
		RelayURL:      normalized.RelayURL,
		RoomID:        normalized.RoomID,
		RoomName:      normalized.RoomName,
		RoomSecret:    base64.StdEncoding.EncodeToString(normalized.RoomSecret[:]),
		CryptoSuiteID: normalized.CryptoSuiteID,
	}
	plainBytes, err := json.Marshal(plain)
	if err != nil {
		return Config{}, err
	}

	var nonce [passwordWrapNonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Config{}, err
	}

	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return Config{}, err
	}
	aad := buildPasswordAAD(salt[:], verifier[:], nonce[:])
	ciphertext := aead.Seal(nil, nonce[:], plainBytes, aad)

	normalized.PasswordRequired = true
	normalized.PasswordSalt = salt
	normalized.PasswordVerifier = verifier
	normalized.passwordWrapNonce = nonce
	normalized.passwordWrapCiphertext = ciphertext
	return normalized, nil
}

func (c Config) RequiresPassword() bool {
	return c.PasswordRequired
}

func (c Config) VerifyPassword(password string) bool {
	if !c.PasswordRequired {
		return true
	}
	derived, _, err := derivePasswordMaterial(password, c.PasswordSalt)
	if err != nil {
		return false
	}
	return hmac.Equal(derived[:], c.PasswordVerifier[:])
}

func (c Config) IsLocked() bool {
	if !c.PasswordRequired {
		return false
	}
	return len(c.passwordWrapCiphertext) > 0 && c.RelayURL == "" && c.RoomID == ""
}

// UnlockWithPassword decrypts password-protected invite metadata and room secret.
func (c Config) UnlockWithPassword(password string) (Config, error) {
	if !c.PasswordRequired {
		return c, nil
	}
	if len(c.passwordWrapCiphertext) == 0 {
		if c.RelayURL == "" || c.RoomID == "" {
			return Config{}, ErrInviteLocked
		}
		return c, nil
	}

	verifier, wrapKey, err := derivePasswordMaterial(password, c.PasswordSalt)
	if err != nil {
		return Config{}, err
	}
	if subtle.ConstantTimeCompare(verifier[:], c.PasswordVerifier[:]) != 1 {
		return Config{}, ErrInvalidPassword
	}

	aead, err := chacha20poly1305.New(wrapKey)
	if err != nil {
		return Config{}, err
	}
	aad := buildPasswordAAD(c.PasswordSalt[:], c.PasswordVerifier[:], c.passwordWrapNonce[:])
	plainBytes, err := aead.Open(nil, c.passwordWrapNonce[:], c.passwordWrapCiphertext, aad)
	if err != nil {
		return Config{}, ErrInvalidPassword
	}

	var protected protectedPayloadPlaintext
	if err := json.Unmarshal(plainBytes, &protected); err != nil {
		return Config{}, fmt.Errorf("%w: malformed protected payload", ErrInviteInvalidPayload)
	}
	decodedSecret, err := base64.StdEncoding.DecodeString(protected.RoomSecret)
	if err != nil || len(decodedSecret) != roomcrypto.RoomSecretSize {
		return Config{}, fmt.Errorf("%w: invalid protected room_secret", ErrInviteInvalidPayload)
	}

	out := c
	out.RelayURL = protected.RelayURL
	out.RoomID = protected.RoomID
	out.RoomName = protected.RoomName
	out.CryptoSuiteID = protected.CryptoSuiteID
	copy(out.RoomSecret[:], decodedSecret)

	out, err = normalizeUnlockedConfig(out)
	if err != nil {
		return Config{}, err
	}
	return out, nil
}

func MarshalFooter(cfg Config) ([]byte, error) {
	payload, err := marshalPayload(cfg)
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

func normalizeUnlockedConfig(cfg Config) (Config, error) {
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
	return cfg, nil
}

func marshalPayload(cfg Config) ([]byte, error) {
	if cfg.PasswordRequired {
		if len(cfg.passwordWrapCiphertext) == 0 {
			return nil, fmt.Errorf("%w: password-protected config missing wrapped payload (use ProtectWithPassword)", ErrInviteInvalidPayload)
		}
		out := make([]byte, 0, 1+1+passwordSaltSize+passwordVerifierSize+passwordWrapNonceSize+len(cfg.passwordWrapCiphertext))
		out = append(out, PayloadVersion)
		out = append(out, payloadModePasswordWrapped)
		out = append(out, cfg.PasswordSalt[:]...)
		out = append(out, cfg.PasswordVerifier[:]...)
		out = append(out, cfg.passwordWrapNonce[:]...)
		out = append(out, cfg.passwordWrapCiphertext...)
		return out, nil
	}

	normalized, err := normalizeUnlockedConfig(cfg)
	if err != nil {
		return nil, err
	}
	return marshalLegacyPayload(normalized)
}

func parsePayload(payload []byte) (Config, error) {
	if len(payload) == 0 {
		return Config{}, ErrInviteInvalidPayload
	}

	switch payload[0] {
	case payloadVersionLegacy:
		return parseLegacyPayload(payload)
	case PayloadVersion:
		return parsePayloadV2(payload)
	default:
		return Config{}, fmt.Errorf("%w: unsupported payload version %d", ErrInviteInvalidPayload, payload[0])
	}
}

func parsePayloadV2(payload []byte) (Config, error) {
	if len(payload) < 2 {
		return Config{}, ErrInviteInvalidPayload
	}
	mode := payload[1]
	if mode != payloadModePasswordWrapped && mode != payloadModeUnprotected {
		return Config{}, fmt.Errorf("%w: unsupported payload mode %d", ErrInviteInvalidPayload, mode)
	}

	if mode == payloadModeUnprotected {
		if len(payload) < 2+1 {
			return Config{}, ErrInviteInvalidPayload
		}
		legacy := make([]byte, 0, len(payload)-1)
		legacy = append(legacy, payloadVersionLegacy)
		legacy = append(legacy, payload[2:]...)
		return parseLegacyPayload(legacy)
	}

	minLen := 2 + passwordSaltSize + passwordVerifierSize + passwordWrapNonceSize + chacha20poly1305.Overhead
	if len(payload) < minLen {
		return Config{}, ErrInviteInvalidPayload
	}

	pos := 2
	cfg := Config{PasswordRequired: true}
	copy(cfg.PasswordSalt[:], payload[pos:pos+passwordSaltSize])
	pos += passwordSaltSize
	copy(cfg.PasswordVerifier[:], payload[pos:pos+passwordVerifierSize])
	pos += passwordVerifierSize
	copy(cfg.passwordWrapNonce[:], payload[pos:pos+passwordWrapNonceSize])
	pos += passwordWrapNonceSize
	cfg.passwordWrapCiphertext = append([]byte(nil), payload[pos:]...)
	if len(cfg.passwordWrapCiphertext) < chacha20poly1305.Overhead {
		return Config{}, ErrInviteInvalidPayload
	}

	return cfg, nil
}

func marshalLegacyPayload(cfg Config) ([]byte, error) {
	plain := payloadPlaintextLegacy{
		RelayURL:      cfg.RelayURL,
		RoomID:        cfg.RoomID,
		RoomName:      cfg.RoomName,
		CryptoSuiteID: cfg.CryptoSuiteID,
	}
	plainBytes, err := json.Marshal(plain)
	if err != nil {
		return nil, err
	}

	var salt [legacySaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	var nonce [legacyNonceSize]byte
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

	aad := buildInviteAAD(cfg.RoomSecret[:], salt[:], nonce[:])
	ciphertext := aead.Seal(nil, nonce[:], plainBytes, aad)

	out := make([]byte, 0, 1+roomcrypto.RoomSecretSize+legacySaltSize+legacyNonceSize+len(ciphertext))
	out = append(out, payloadVersionLegacy)
	out = append(out, cfg.RoomSecret[:]...)
	out = append(out, salt[:]...)
	out = append(out, nonce[:]...)
	out = append(out, ciphertext...)
	return out, nil
}

func parseLegacyPayload(payload []byte) (Config, error) {
	minLen := 1 + roomcrypto.RoomSecretSize + legacySaltSize + legacyNonceSize + chacha20poly1305.Overhead
	if len(payload) < minLen {
		return Config{}, ErrInviteInvalidPayload
	}
	if payload[0] != payloadVersionLegacy {
		return Config{}, fmt.Errorf("%w: unsupported payload version %d", ErrInviteInvalidPayload, payload[0])
	}

	var secret [roomcrypto.RoomSecretSize]byte
	copy(secret[:], payload[1:1+roomcrypto.RoomSecretSize])
	saltStart := 1 + roomcrypto.RoomSecretSize
	nonceStart := saltStart + legacySaltSize
	cipherStart := nonceStart + legacyNonceSize
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

	aad := buildInviteAAD(secret[:], salt, nonce)
	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return Config{}, fmt.Errorf("%w: auth/decrypt failed", ErrInviteInvalidPayload)
	}

	var parsed payloadPlaintextLegacy
	if err := json.Unmarshal(plaintext, &parsed); err != nil {
		return Config{}, fmt.Errorf("%w: malformed payload json", ErrInviteInvalidPayload)
	}

	cfg := Config{
		RelayURL:      parsed.RelayURL,
		RoomID:        parsed.RoomID,
		RoomName:      parsed.RoomName,
		RoomSecret:    secret,
		CryptoSuiteID: parsed.CryptoSuiteID,
	}

	cfg, err = normalizeUnlockedConfig(cfg)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func deriveInviteKey(roomSecret, salt []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, roomSecret, salt, "encryptroom/invite-key/v1", chacha20poly1305.KeySize)
}

func derivePasswordMaterial(password string, salt [passwordSaltSize]byte) ([passwordVerifierSize]byte, []byte, error) {
	if password == "" {
		return [passwordVerifierSize]byte{}, nil, errors.New("password cannot be empty")
	}

	derived := argon2.IDKey(
		[]byte(password),
		salt[:],
		passwordKDFTime,
		passwordKDFMemoryKiB,
		passwordKDFParallelism,
		passwordDerivedKeySize,
	)

	verifier := sha256.Sum256(append([]byte("encryptroom/password-verifier/v2:"), derived...))
	wrapKey, err := hkdf.Key(sha256.New, derived, salt[:], "encryptroom/password-wrap-key/v2", chacha20poly1305.KeySize)
	if err != nil {
		return [passwordVerifierSize]byte{}, nil, err
	}
	return verifier, wrapKey, nil
}

func buildInviteAAD(roomSecret, salt, nonce []byte) []byte {
	aad := make([]byte, 0, len(roomSecret)+len(salt)+len(nonce)+32)
	aad = append(aad, []byte("encryptroom/invite-envelope/v1")...)
	aad = append(aad, roomSecret...)
	aad = append(aad, salt...)
	aad = append(aad, nonce...)
	return aad
}

func buildPasswordAAD(salt, verifier, nonce []byte) []byte {
	aad := make([]byte, 0, len(salt)+len(verifier)+len(nonce)+48)
	aad = append(aad, []byte("encryptroom/invite-password-wrap/v2")...)
	aad = append(aad, salt...)
	aad = append(aad, verifier...)
	aad = append(aad, nonce...)
	return aad
}
