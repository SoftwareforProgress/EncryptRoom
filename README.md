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

See `SECURITY.md` for details.

## v1 protocol summary

### Room secret and room ID

- Invite contains a 32-byte high-entropy room secret.
- `room_id` is derived from room secret (`SHA-256`-based derivation, truncated hex).

### Relay authentication (no password sent)

- Client derives `room_auth_verifier = HMAC-SHA256(room_secret, "encryptroom/relay-auth/v1")`.
- Relay sends random challenge.
- Client returns `HMAC-SHA256(room_auth_verifier, challenge)`.
- Relay verifies using room verifier it tracks in-memory per room.

### Message encryption

- Sender uses one ephemeral X25519 keypair per process session.
- Session subkey derived with X25519 + HKDF-SHA256.
- Payload encrypted with ChaCha20-Poly1305.
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
- `/internal/crypto`: room/message crypto APIs
- `/internal/invite`: invite payload/footer parsing and writing
- `/internal/protocol`: handshake control protocol

## Invite format

Binary footer appended to client executable:

1. `MAGIC` (`ERINV1\0`)
2. `uint32` footer version
3. `uint32` payload length
4. payload bytes

Payload contains room secret plus encrypted+authenticated config fields:

- `relay_url`
- `room_id`
- `room_secret`
- `crypto_suite_id`

For development, client can load an external invite file (`-invite-file`).

## Usage

### 1. Start relay

```bash
go run ./cmd/encryptroom-relay -listen :8080
```

### 2. Generate invite (dev)

```bash
go run ./cmd/encryptroom-invite -relay-url tcp://127.0.0.1:8080 -out invite.bin
```

### 3. Run client in dev mode (external invite)

```bash
go run ./cmd/encryptroom -invite-file invite.bin
```

Run in a second terminal with the same invite to chat in the same room.

### 4. Build shipping binary with embedded invite

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
