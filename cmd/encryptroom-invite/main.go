package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/fyroc/encryptroom/internal/invite"
)

func main() {
	relayURL := flag.String("relay-url", "", "relay TCP URL (required), e.g. tcp://127.0.0.1:8080")
	inviteOut := flag.String("out", "invite.bin", "output invite file path")
	secretHex := flag.String("room-secret", "", "optional 32-byte room secret in hex")
	appendBinary := flag.String("append-binary", "", "optional input binary to append invite footer")
	binaryOut := flag.String("binary-out", "", "output path for binary with embedded invite")
	flag.Parse()

	if *relayURL == "" {
		fmt.Fprintln(os.Stderr, "-relay-url is required")
		os.Exit(1)
	}

	secret, err := parseOrGenerateSecret(*secretHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid room secret: %v\n", err)
		os.Exit(1)
	}

	cfg := invite.Config{
		RelayURL:      *relayURL,
		RoomSecret:    secret,
		CryptoSuiteID: invite.CryptoSuiteIDV1,
	}

	footer, err := invite.MarshalFooter(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build invite: %v\n", err)
		os.Exit(1)
	}
	parsed, err := invite.ParseFooter(footer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to validate invite: %v\n", err)
		os.Exit(1)
	}

	if err := invite.WriteInviteToFile(*inviteOut, parsed); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write invite file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("invite written to %s\n", *inviteOut)
	fmt.Printf("room_id: %s\n", parsed.RoomID)
	fmt.Printf("room_secret_hex: %s\n", hex.EncodeToString(parsed.RoomSecret[:]))

	if *appendBinary != "" {
		if *binaryOut == "" {
			fmt.Fprintln(os.Stderr, "-binary-out is required with -append-binary")
			os.Exit(1)
		}
		if err := invite.WriteInviteToBinary(*appendBinary, *binaryOut, parsed); err != nil {
			fmt.Fprintf(os.Stderr, "failed to append invite to binary: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("binary with embedded invite written to %s\n", *binaryOut)
	}
}

func parseOrGenerateSecret(secretHex string) ([32]byte, error) {
	if secretHex == "" {
		return invite.GenerateRoomSecret()
	}
	decoded, err := hex.DecodeString(secretHex)
	if err != nil {
		return [32]byte{}, err
	}
	if len(decoded) != 32 {
		return [32]byte{}, fmt.Errorf("expected 32 bytes, got %d", len(decoded))
	}
	var secret [32]byte
	copy(secret[:], decoded)
	return secret, nil
}
