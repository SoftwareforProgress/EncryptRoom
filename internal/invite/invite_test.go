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

func TestMarshalParsePasswordVerifierRoundTrip(t *testing.T) {
	secret := [32]byte{}
	for i := 0; i < len(secret); i++ {
		secret[i] = byte(i + 1)
	}
	base := Config{
		RelayURL:      "tcp://127.0.0.1:8080",
		RoomName:      "Friends Night",
		RoomSecret:    secret,
		CryptoSuiteID: CryptoSuiteIDV1,
	}
	cfg, err := ProtectWithPassword(base, "pw123")
	if err != nil {
		t.Fatalf("ProtectWithPassword: %v", err)
	}

	footer, err := MarshalFooter(cfg)
	if err != nil {
		t.Fatalf("MarshalFooter: %v", err)
	}

	parsed, err := ParseFooter(footer)
	if err != nil {
		t.Fatalf("ParseFooter: %v", err)
	}
	if !parsed.PasswordRequired {
		t.Fatal("expected password required")
	}
	if bytes.Contains(footer, secret[:]) {
		t.Fatal("plaintext room secret should not appear in protected footer")
	}
	if !parsed.VerifyPassword("pw123") {
		t.Fatal("expected password verification to succeed")
	}
	if parsed.VerifyPassword("wrong") {
		t.Fatal("expected wrong password to fail")
	}
	if parsed.RoomID != "" || parsed.RelayURL != "" {
		t.Fatal("expected protected invite to remain locked before password unlock")
	}

	unlocked, err := parsed.UnlockWithPassword("pw123")
	if err != nil {
		t.Fatalf("UnlockWithPassword: %v", err)
	}
	if unlocked.RoomName != cfg.RoomName {
		t.Fatalf("room name mismatch after unlock: got %q", unlocked.RoomName)
	}
	if !bytes.Equal(unlocked.RoomSecret[:], secret[:]) {
		t.Fatal("room secret mismatch after unlock")
	}

	if _, err := parsed.UnlockWithPassword("wrong"); err == nil {
		t.Fatal("expected unlock failure for wrong password")
	}
}

func TestProtectedInviteTamperFailsOnUnlock(t *testing.T) {
	secret := [32]byte{}
	for i := 0; i < len(secret); i++ {
		secret[i] = byte(i + 1)
	}
	base := Config{
		RelayURL:      "tcp://127.0.0.1:8080",
		RoomName:      "Friends Night",
		RoomSecret:    secret,
		CryptoSuiteID: CryptoSuiteIDV1,
	}
	cfg, err := ProtectWithPassword(base, "pw123")
	if err != nil {
		t.Fatalf("ProtectWithPassword: %v", err)
	}
	footer, err := MarshalFooter(cfg)
	if err != nil {
		t.Fatalf("MarshalFooter: %v", err)
	}

	footer[len(footer)-1] ^= 0xFF
	parsed, err := ParseFooter(footer)
	if err != nil {
		t.Fatalf("ParseFooter: %v", err)
	}
	if _, err := parsed.UnlockWithPassword("pw123"); err == nil {
		t.Fatal("expected unlock failure for tampered protected payload")
	}
}
