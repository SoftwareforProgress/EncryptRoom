# EncryptRoom

EncryptRoom is a private, stateless terminal chatroom in Go.

- Architecture: untrusted relay server + outbound clients.
- Relay forwards ciphertext only and stores no history.
- Presence-based messaging: offline clients miss messages.
- Access model: possession of an invite grants room access.

## Threat model (v1)

### Relay compromise: what attackers can do

- Drop, delay, or reorder packets (DoS).
- Observe traffic metadata (timing, packet sizes, room activity).
- Read ciphertext frames.

### Relay compromise: what attackers cannot do

- Decrypt chat payloads without room secret material.
- Recover plaintext display names/messages from opaque forwarded frames.

### Limitations

- A compromised client can reveal room secrets and plaintext.
- Membership revocation requires rotating to a new room secret/invite.
- No anonymity against network observers: relay connection endpoints are visible at the network layer.
- If you run relays over `tcp://` (no TLS), network observers can still read relay handshake metadata and traffic timing.

See `SECURITY.md` for details.

## v1 protocol summary

### Room secret and room ID

- Room secret is 32-byte high entropy.
- For password-protected invites, the binary stores a password-wrapped room secret (not plaintext room secret).
- `room_id` is derived from room secret (`SHA-256`-based derivation, truncated hex).

### Relay authentication (no password sent)

- Client derives `room_auth_verifier = HMAC-SHA256(room_secret, "encryptroom/relay-auth/v1")`.
- Relay sends random challenge.
- Client returns `HMAC-SHA256(room_auth_verifier, challenge)`.
- Relay requests/verifies room verifier only when a room is first created in memory; normal joins use challenge-response without sending a reusable verifier.
- Relay verifies using room verifier it tracks in-memory per room.

### Message encryption

- Sender uses one ephemeral X25519 keypair per process session.
- Session subkey derived with X25519 + HKDF-SHA256.
- Payload encrypted with ChaCha20-Poly1305.
- Message nonce is deterministic from the per-sender monotonic counter (no nonce reuse under one sender session key).
- Each message includes:
  - version
  - sender ephemeral public key
  - monotonic counter
  - nonce
  - ciphertext+tag
- Receiver enforces strictly increasing counters per sender key (replay rejection).

### Security properties provided

- Confidentiality/integrity of message payloads (assuming room secret stays secret).
- Replay detection for duplicate/out-of-order messages per sender session.
- Stateless relay operation with no message persistence.

### Not provided in v1

- Automatic group membership rekeying.
- Strong post-compromise guarantees after client compromise.
- Advanced metadata protection.

## Repository layout

- `/cmd/encryptroom`: terminal client
- `/cmd/encryptroom-relay`: untrusted relay
- `/cmd/encryptroom-invite`: dev invite generator / embed helper
- `/cmd/encryptroom-api`: HTTP API for creating downloadable room bundles
- `/internal/crypto`: room/message crypto APIs
- `/internal/invite`: invite payload/footer parsing and writing
- `/internal/protocol`: handshake control protocol
- `/internal/provision`: API provisioning helpers (room secret/id generation + validation)

Security-focused tests cover:
- crypto tamper/replay/malformed-frame handling
- protocol frame size enforcement
- relay authentication checks and opaque ciphertext forwarding behavior

## Invite format

Binary footer appended to client executable:

1. `MAGIC` (`ERINV1\0`)
2. `uint32` footer version
3. `uint32` payload length
4. payload bytes

Payload supports two modes:

- Unprotected/dev invites: legacy embedded room secret mode.
- Password-protected invites:
  - room secret and metadata are encrypted with a password-derived key (`Argon2id` + `ChaCha20-Poly1305`)
  - password verifier is derived locally and compared client-side only
  - plaintext room secret is not present in the binary footer

For development, client can load an external invite file (`-invite-file`).

## Usage

### 1. Start relay

```bash
go run ./cmd/encryptroom-relay -listen :8080
```

Optional TLS with existing cert/key:

```bash
go run ./cmd/encryptroom-relay \
  -listen :443 \
  -tls-cert-file /path/fullchain.pem \
  -tls-key-file /path/privkey.pem
```

Optional TLS with Let's Encrypt autocert:

```bash
go run ./cmd/encryptroom-relay \
  -listen :443 \
  -tls-autocert-domains chat.example.com \
  -tls-autocert-email admin@example.com \
  -tls-autocert-http-addr :80
```

### 2. Run API server for React app bundle generation

```bash
go run ./cmd/encryptroom-api \
  -listen :8090 \
  -relay-url tcp://127.0.0.1:8080
```

For production relay TLS, set `-relay-url tls://chat.example.com:443`.

### 3. Create/download a 3-binary bundle via API

```bash
curl -X POST http://127.0.0.1:8090/api/v1/bundles \
  -H 'Content-Type: application/json' \
  -d '{"chat_name":"friends-night","password":"correct horse battery staple"}' \
  --output encryptroom-bundle.zip
```

The zip contains:

- Windows client binary (`.exe`)
- macOS client binary
- Linux client binary
- `README.txt`, `RUN-WINDOWS.txt`, `RUN-MACOS.txt`, and `RUN-LINUX.txt` with per-OS run steps

Each binary has the invite embedded in its footer, so “possession equals access”.

### 4. React usage example

```ts
const res = await fetch("http://127.0.0.1:8090/api/v1/bundles", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    chat_name: "friends-night",
    password: "correct horse battery staple",
    // relay_url is optional if API server has -relay-url default
  }),
});

if (!res.ok) throw new Error("Failed to create room bundle");
const blob = await res.blob();
const href = URL.createObjectURL(blob);
const a = document.createElement("a");
a.href = href;
a.download = "encryptroom-bundle.zip";
a.click();
URL.revokeObjectURL(href);
```

### 5. Run client from extracted binary

Start the binary and enter display name. If the invite was created via API, it then prompts for the room password used in API creation (hidden terminal input).
On success it connects and shows the room name from the invite (for example: `friends-night (room_id)`).
Peers receive encrypted presence notices when a client joins or gracefully exits (`Ctrl+C`, `/exit`, `/quit`).

### 6. Alternative dev mode (external invite file)

```bash
go run ./cmd/encryptroom-invite -relay-url tcp://127.0.0.1:8080 -out invite.bin
go run ./cmd/encryptroom -invite-file invite.bin
```

Run in a second terminal with the same invite to chat in the same room.

### 7. Manual single binary embedding (without API)

```bash
go build -o encryptroom ./cmd/encryptroom
go run ./cmd/encryptroom-invite \
  -relay-url tcp://127.0.0.1:8080 \
  -append-binary ./encryptroom \
  -binary-out ./encryptroom-roomA
./encryptroom-roomA
```

## Development checks

Commands defined in `AGENTS.md`:

```bash
go test ./...
go vet ./...
```
