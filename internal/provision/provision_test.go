package provision

import (
	"errors"
	"testing"
)

func TestBuildInviteConfigValidatesInput(t *testing.T) {
	_, _, err := BuildInviteConfig(BundleRequest{Password: "pw", RelayURL: "tcp://127.0.0.1:8080"}, "")
	if !errors.Is(err, ErrChatNameRequired) {
		t.Fatalf("expected ErrChatNameRequired, got %v", err)
	}

	_, _, err = BuildInviteConfig(BundleRequest{ChatName: "room", RelayURL: "tcp://127.0.0.1:8080"}, "")
	if !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("expected ErrPasswordRequired, got %v", err)
	}

	_, _, err = BuildInviteConfig(BundleRequest{ChatName: "room", Password: "pw"}, "")
	if !errors.Is(err, ErrRelayURLRequired) {
		t.Fatalf("expected ErrRelayURLRequired, got %v", err)
	}
}

func TestBuildInviteConfigUniqueRoomIDs(t *testing.T) {
	req := BundleRequest{
		ChatName: "Friends Room",
		Password: "supersecret",
		RelayURL: "tcp://127.0.0.1:8080",
	}

	cfg1, slug1, err := BuildInviteConfig(req, "")
	if err != nil {
		t.Fatalf("BuildInviteConfig #1: %v", err)
	}
	cfg2, slug2, err := BuildInviteConfig(req, "")
	if err != nil {
		t.Fatalf("BuildInviteConfig #2: %v", err)
	}

	if slug1 != "friends-room" || slug2 != "friends-room" {
		t.Fatalf("unexpected slug values: %q %q", slug1, slug2)
	}
	if cfg1.RoomID == cfg2.RoomID {
		t.Fatalf("expected unique room IDs, got same %q", cfg1.RoomID)
	}
	if cfg1.RelayURL != req.RelayURL {
		t.Fatalf("relay mismatch: %q", cfg1.RelayURL)
	}
	if cfg1.CryptoSuiteID == "" {
		t.Fatal("missing crypto suite id")
	}
	if cfg1.RoomName != req.ChatName {
		t.Fatalf("room name mismatch: got %q want %q", cfg1.RoomName, req.ChatName)
	}
	if !cfg1.PasswordRequired {
		t.Fatal("expected password to be required")
	}
	if !cfg1.VerifyPassword(req.Password) {
		t.Fatal("expected password verification to succeed")
	}
	if cfg1.VerifyPassword("wrong-password") {
		t.Fatal("expected wrong password verification to fail")
	}
}

func TestSlug(t *testing.T) {
	cases := map[string]string{
		"Hello World":        "hello-world",
		"    ":               "chat",
		"a_b$c":              "a-b-c",
		"Ends --- Dashes --": "ends-dashes",
	}
	for input, want := range cases {
		if got := Slug(input); got != want {
			t.Fatalf("Slug(%q) = %q, want %q", input, got, want)
		}
	}
}
