package invite

import (
	"bytes"
	"testing"
)

func TestMarshalParseFooterRoundTrip(t *testing.T) {
	secret := [32]byte{}
	for i := 0; i < len(secret); i++ {
		secret[i] = byte(i + 1)
	}

	cfg := Config{
		RelayURL:      "tcp://127.0.0.1:8080",
		RoomSecret:    secret,
		CryptoSuiteID: CryptoSuiteIDV1,
	}

	footer, err := MarshalFooter(cfg)
	if err != nil {
		t.Fatalf("MarshalFooter: %v", err)
	}

	parsed, err := ParseFooter(footer)
	if err != nil {
		t.Fatalf("ParseFooter: %v", err)
	}
	if parsed.RelayURL != cfg.RelayURL {
		t.Fatalf("relay mismatch: got %q", parsed.RelayURL)
	}
	if !bytes.Equal(parsed.RoomSecret[:], cfg.RoomSecret[:]) {
		t.Fatal("room secret mismatch")
	}
	if parsed.RoomID == "" {
		t.Fatal("room id should be derived")
	}
}

func TestMarshalRejectsRoomIDMismatch(t *testing.T) {
	secret := [32]byte{}
	for i := 0; i < len(secret); i++ {
		secret[i] = byte(i + 1)
	}
	cfg := Config{
		RelayURL:      "tcp://127.0.0.1:8080",
		RoomSecret:    secret,
		RoomID:        "deadbeef",
		CryptoSuiteID: CryptoSuiteIDV1,
	}
	if _, err := MarshalFooter(cfg); err == nil {
		t.Fatal("expected error for mismatched room_id")
	}
}

func TestParseRejectsTamperedPayload(t *testing.T) {
	secret := [32]byte{}
	for i := 0; i < len(secret); i++ {
		secret[i] = byte(i + 1)
	}

	cfg := Config{
		RelayURL:      "tcp://127.0.0.1:8080",
		RoomSecret:    secret,
		CryptoSuiteID: CryptoSuiteIDV1,
	}
	footer, err := MarshalFooter(cfg)
	if err != nil {
		t.Fatalf("MarshalFooter: %v", err)
	}
	footer[len(footer)-1] ^= 0xFF
	if _, err := ParseFooter(footer); err == nil {
		t.Fatal("expected parse error on tampered payload")
	}
}
