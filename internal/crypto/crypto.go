package crypto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	RoomSecretSize           = 32
	SenderPublicKeySize      = 32
	messageVersion      byte = 1
	nonceSize                = chacha20poly1305.NonceSize
	headerSize               = 1 + SenderPublicKeySize + 8 + nonceSize
)

var (
	ErrInvalidSecretSize  = errors.New("invalid room secret size")
	ErrInvalidMessage     = errors.New("invalid encrypted message")
	ErrUnsupportedVersion = errors.New("unsupported message version")
	ErrReplayDetected     = errors.New("replay detected")
)

// Session owns one ephemeral sender key for the process lifetime and validates replays.
type Session struct {
	roomSecret    [RoomSecretSize]byte
	roomPrivate   *ecdh.PrivateKey
	roomPublic    *ecdh.PublicKey
	senderPrivate *ecdh.PrivateKey
	senderPublic  [SenderPublicKeySize]byte

	mu          sync.Mutex
	sendCounter uint64
	recvMax     map[[SenderPublicKeySize]byte]uint64
}

func NewSession(roomSecret []byte) (*Session, error) {
	if len(roomSecret) != RoomSecretSize {
		return nil, ErrInvalidSecretSize
	}

	var secret [RoomSecretSize]byte
	copy(secret[:], roomSecret)

	curve := ecdh.X25519()
	roomPrivate, err := curve.NewPrivateKey(secret[:])
	if err != nil {
		return nil, err
	}

	senderPrivate, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	var senderPublic [SenderPublicKeySize]byte
	copy(senderPublic[:], senderPrivate.PublicKey().Bytes())

	return &Session{
		roomSecret:    secret,
		roomPrivate:   roomPrivate,
		roomPublic:    roomPrivate.PublicKey(),
		senderPrivate: senderPrivate,
		senderPublic:  senderPublic,
		recvMax:       make(map[[SenderPublicKeySize]byte]uint64),
	}, nil
}

func (s *Session) SenderPublicKey() [SenderPublicKeySize]byte {
	return s.senderPublic
}

func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	s.sendCounter++
	counter := s.sendCounter
	s.mu.Unlock()

	shared, err := s.senderPrivate.ECDH(s.roomPublic)
	if err != nil {
		return nil, err
	}

	key, err := deriveAEADKey(shared, s.roomSecret[:], s.senderPublic[:])
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	header := make([]byte, headerSize)
	header[0] = messageVersion
	copy(header[1:1+SenderPublicKeySize], s.senderPublic[:])
	binary.BigEndian.PutUint64(header[1+SenderPublicKeySize:1+SenderPublicKeySize+8], counter)
	copy(header[1+SenderPublicKeySize+8:], nonce)

	ciphertext := aead.Seal(nil, nonce, plaintext, header)
	out := make([]byte, 0, len(header)+len(ciphertext))
	out = append(out, header...)
	out = append(out, ciphertext...)
	return out, nil
}

func (s *Session) Decrypt(message []byte) ([]byte, [SenderPublicKeySize]byte, uint64, error) {
	var sender [SenderPublicKeySize]byte

	if len(message) < headerSize+chacha20poly1305.Overhead {
		return nil, sender, 0, ErrInvalidMessage
	}
	if message[0] != messageVersion {
		return nil, sender, 0, ErrUnsupportedVersion
	}

	copy(sender[:], message[1:1+SenderPublicKeySize])
	counter := binary.BigEndian.Uint64(message[1+SenderPublicKeySize : 1+SenderPublicKeySize+8])
	nonce := message[1+SenderPublicKeySize+8 : headerSize]
	header := message[:headerSize]
	ciphertext := message[headerSize:]

	curve := ecdh.X25519()
	senderPub, err := curve.NewPublicKey(sender[:])
	if err != nil {
		return nil, sender, 0, ErrInvalidMessage
	}

	shared, err := s.roomPrivate.ECDH(senderPub)
	if err != nil {
		return nil, sender, 0, err
	}

	key, err := deriveAEADKey(shared, s.roomSecret[:], sender[:])
	if err != nil {
		return nil, sender, 0, err
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, sender, 0, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, sender, 0, err
	}

	s.mu.Lock()
	last := s.recvMax[sender]
	if counter <= last {
		s.mu.Unlock()
		return nil, sender, counter, ErrReplayDetected
	}
	s.recvMax[sender] = counter
	s.mu.Unlock()

	return plaintext, sender, counter, nil
}

func DeriveRoomID(roomSecret []byte) (string, error) {
	if len(roomSecret) != RoomSecretSize {
		return "", ErrInvalidSecretSize
	}
	h := sha256.New()
	h.Write([]byte("encryptroom/room-id/v1"))
	h.Write(roomSecret)
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16]), nil
}

func deriveAEADKey(shared, roomSecret, senderPub []byte) ([]byte, error) {
	info := make([]byte, 0, len("encryptroom/session-key/v1:")+len(senderPub))
	info = append(info, []byte("encryptroom/session-key/v1:")...)
	info = append(info, senderPub...)
	return hkdf.Key(sha256.New, shared, roomSecret, string(info), chacha20poly1305.KeySize)
}
