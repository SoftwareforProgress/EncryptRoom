package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	ProtocolVersion = 1
	challengeSize   = 32
	verifierSize    = 32

	FrameTypeHello      byte = 1
	FrameTypeChallenge  byte = 2
	FrameTypeAuth       byte = 3
	FrameTypeAuthOK     byte = 4
	FrameTypeAuthError  byte = 5
	FrameTypeCiphertext byte = 6

	maxFrameSize = 1 << 20 // 1 MiB
)

var (
	ErrFrameTooLarge       = errors.New("frame exceeds max size")
	ErrInvalidChallenge    = errors.New("invalid challenge payload")
	ErrInvalidAuthResponse = errors.New("invalid auth response payload")
)

// HelloPayload is sent by clients before challenge-response authentication.
type HelloPayload struct {
	Proto    int    `json:"proto"`
	RoomID   string `json:"room_id"`
	RoomAuth string `json:"room_auth,omitempty"`
}

// DeriveRoomAuthVerifier derives a relay-verifiable room key from the room secret.
func DeriveRoomAuthVerifier(roomSecret [32]byte) [32]byte {
	mac := hmac.New(sha256.New, roomSecret[:])
	mac.Write([]byte("encryptroom/relay-auth/v1"))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func NewChallenge() ([challengeSize]byte, error) {
	var c [challengeSize]byte
	_, err := rand.Read(c[:])
	return c, err
}

func ComputeChallengeResponse(verifier [32]byte, challenge [challengeSize]byte) [32]byte {
	mac := hmac.New(sha256.New, verifier[:])
	mac.Write(challenge[:])
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func VerifyChallengeResponse(verifier [32]byte, challenge [challengeSize]byte, response [32]byte) bool {
	expected := ComputeChallengeResponse(verifier, challenge)
	return hmac.Equal(expected[:], response[:])
}

func EncodeChallenge(challenge [challengeSize]byte, requireVerifier bool) []byte {
	payload := make([]byte, 1+challengeSize)
	if requireVerifier {
		payload[0] = 1
	}
	copy(payload[1:], challenge[:])
	return payload
}

func DecodeChallenge(payload []byte) ([challengeSize]byte, bool, error) {
	var challenge [challengeSize]byte
	if len(payload) != 1+challengeSize {
		return challenge, false, ErrInvalidChallenge
	}
	requireVerifier := payload[0] == 1
	copy(challenge[:], payload[1:])
	return challenge, requireVerifier, nil
}

func EncodeAuthResponse(response [challengeSize]byte, verifier *[verifierSize]byte) []byte {
	if verifier == nil {
		payload := make([]byte, challengeSize)
		copy(payload, response[:])
		return payload
	}

	payload := make([]byte, challengeSize+verifierSize)
	copy(payload[:challengeSize], response[:])
	copy(payload[challengeSize:], verifier[:])
	return payload
}

func DecodeAuthResponse(payload []byte) ([challengeSize]byte, *[verifierSize]byte, error) {
	var response [challengeSize]byte
	switch len(payload) {
	case challengeSize:
		copy(response[:], payload)
		return response, nil, nil
	case challengeSize + verifierSize:
		copy(response[:], payload[:challengeSize])
		var verifier [verifierSize]byte
		copy(verifier[:], payload[challengeSize:])
		return response, &verifier, nil
	default:
		return response, nil, ErrInvalidAuthResponse
	}
}

func WriteFrame(w io.Writer, frameType byte, payload []byte) error {
	if len(payload) > maxFrameSize {
		return ErrFrameTooLarge
	}

	var header [5]byte
	header[0] = frameType
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(payload) == 0 {
		return nil
	}
	_, err := w.Write(payload)
	return err
}

func ReadFrame(r io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}

	frameType := header[0]
	payloadLen := int(binary.BigEndian.Uint32(header[1:]))
	if payloadLen > maxFrameSize {
		return 0, nil, fmt.Errorf("%w: %d", ErrFrameTooLarge, payloadLen)
	}
	if payloadLen == 0 {
		return frameType, nil, nil
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return frameType, payload, nil
}
