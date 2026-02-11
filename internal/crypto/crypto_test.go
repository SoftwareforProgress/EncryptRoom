package crypto

import (
	"errors"
	"testing"
)

func TestEncryptDecryptAndReplay(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	sender, err := NewSession(secret)
	if err != nil {
		t.Fatalf("NewSession(sender): %v", err)
	}
	receiver, err := NewSession(secret)
	if err != nil {
		t.Fatalf("NewSession(receiver): %v", err)
	}

	ciphertext, err := sender.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	plaintext, _, _, err := receiver.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plaintext) != "hello" {
		t.Fatalf("got plaintext %q", plaintext)
	}

	_, _, _, err = receiver.Decrypt(ciphertext)
	if !errors.Is(err, ErrReplayDetected) {
		t.Fatalf("expected replay error, got %v", err)
	}

	ciphertext2, err := sender.Encrypt([]byte("next"))
	if err != nil {
		t.Fatalf("Encrypt second: %v", err)
	}
	plaintext2, _, _, err := receiver.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("Decrypt second: %v", err)
	}
	if string(plaintext2) != "next" {
		t.Fatalf("got plaintext2 %q", plaintext2)
	}
}

func TestDecryptRejectsTamper(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	sender, err := NewSession(secret)
	if err != nil {
		t.Fatalf("NewSession(sender): %v", err)
	}
	receiver, err := NewSession(secret)
	if err != nil {
		t.Fatalf("NewSession(receiver): %v", err)
	}

	ciphertext, err := sender.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ciphertext[len(ciphertext)-1] ^= 0xFF
	if _, _, _, err := receiver.Decrypt(ciphertext); err == nil {
		t.Fatal("expected auth failure on tampered ciphertext")
	}
}
