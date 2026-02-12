package protocol

import (
	"bytes"
	"errors"
	"testing"

	roomcrypto "github.com/fyroc/encryptroom/internal/crypto"
)

func TestChallengeResponseVerification(t *testing.T) {
	secret := [32]byte{}
	for i := 0; i < len(secret); i++ {
		secret[i] = byte(i + 10)
	}
	verifier := DeriveRoomAuthVerifier(secret)

	challenge := [32]byte{}
	for i := 0; i < len(challenge); i++ {
		challenge[i] = byte(i + 1)
	}

	response := ComputeChallengeResponse(verifier, challenge)
	if !VerifyChallengeResponse(verifier, challenge, response) {
		t.Fatal("expected valid response")
	}

	response[0] ^= 0x01
	if VerifyChallengeResponse(verifier, challenge, response) {
		t.Fatal("expected invalid response after tamper")
	}

	otherSecret := [32]byte{}
	otherSecret[0] = 99
	otherVerifier := DeriveRoomAuthVerifier(otherSecret)
	response2 := ComputeChallengeResponse(otherVerifier, challenge)
	if VerifyChallengeResponse(verifier, challenge, response2) {
		t.Fatal("expected invalid response from another verifier")
	}
}

func TestFrameRoundTrip(t *testing.T) {
	payload := []byte("opaque-ciphertext-bytes")
	buf := bytes.NewBuffer(nil)
	if err := WriteFrame(buf, FrameTypeCiphertext, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	frameType, got, err := ReadFrame(buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if frameType != FrameTypeCiphertext {
		t.Fatalf("frame type mismatch: got %d", frameType)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %x want %x", got, payload)
	}
}

func TestWriteFrameRejectsTooLargePayload(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	oversized := make([]byte, maxFrameSize+1)
	err := WriteFrame(buf, FrameTypeCiphertext, oversized)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestReadFrameRejectsTooLargePayload(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.WriteByte(FrameTypeCiphertext)
	buf.Write([]byte{0x00, 0x10, 0x00, 0x01}) // 1,048,577 bytes

	_, _, err := ReadFrame(buf)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}

func TestChallengeEncodingRoundTrip(t *testing.T) {
	challenge := [32]byte{}
	for i := range challenge {
		challenge[i] = byte(i + 1)
	}

	payload := EncodeChallenge(challenge, true)
	gotChallenge, requireVerifier, err := DecodeChallenge(payload)
	if err != nil {
		t.Fatalf("DecodeChallenge: %v", err)
	}
	if !requireVerifier {
		t.Fatal("expected verifier-required flag")
	}
	if gotChallenge != challenge {
		t.Fatalf("challenge mismatch: got %x want %x", gotChallenge, challenge)
	}
}

func TestAuthEncodingRoundTrip(t *testing.T) {
	response := [32]byte{}
	for i := range response {
		response[i] = byte(i + 2)
	}
	verifier := [32]byte{}
	for i := range verifier {
		verifier[i] = byte(i + 3)
	}

	withVerifier := EncodeAuthResponse(response, &verifier)
	gotResp, gotVerifier, err := DecodeAuthResponse(withVerifier)
	if err != nil {
		t.Fatalf("DecodeAuthResponse(withVerifier): %v", err)
	}
	if gotResp != response {
		t.Fatalf("response mismatch with verifier: got %x want %x", gotResp, response)
	}
	if gotVerifier == nil || *gotVerifier != verifier {
		t.Fatal("verifier mismatch")
	}

	withoutVerifier := EncodeAuthResponse(response, nil)
	gotResp, gotVerifier, err = DecodeAuthResponse(withoutVerifier)
	if err != nil {
		t.Fatalf("DecodeAuthResponse(noVerifier): %v", err)
	}
	if gotResp != response {
		t.Fatalf("response mismatch without verifier: got %x want %x", gotResp, response)
	}
	if gotVerifier != nil {
		t.Fatal("expected nil verifier")
	}
}

func TestDeriveRoomIDFromVerifierMatchesCryptoDerivation(t *testing.T) {
	secret := [32]byte{}
	for i := range secret {
		secret[i] = byte(i + 10)
	}
	verifier := DeriveRoomAuthVerifier(secret)
	got := DeriveRoomIDFromVerifier(verifier)

	want, err := roomcrypto.DeriveRoomID(secret[:])
	if err != nil {
		t.Fatalf("DeriveRoomID: %v", err)
	}
	if got != want {
		t.Fatalf("room id mismatch: got %q want %q", got, want)
	}
}
