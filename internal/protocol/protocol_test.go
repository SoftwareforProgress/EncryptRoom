package protocol

import "testing"

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
