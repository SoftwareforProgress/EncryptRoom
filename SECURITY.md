# Security Model (v1)

EncryptRoom is a presence-based encrypted chat over an untrusted relay.

## What this protects

- Relay cannot decrypt chat payloads without the room secret.
- Relay only forwards opaque ciphertext and keeps no message history.
- User display names and messages are only inside encrypted payloads.
- Room password verification is local client-side only and is not sent to the relay.
- Relay accepts only ciphertext frames after authentication and drops connections that send unexpected frame types.
- Relay challenge-response does not transmit a reusable room verifier on normal joins (verifier is only sent when creating a new room in relay memory).

## What this does not protect

- A compromised client can exfiltrate room secrets and plaintext.
- Group membership changes are not retroactive: removing a participant requires rotating to a new invite/room secret.
- Relay compromise still enables denial-of-service, connection disruption, and traffic analysis (timing/volume metadata).
- Network-level observers can still see that a client connects to the relay.
- If you run the bundle-generation API, that API process sees chat name/password inputs at creation time. It should avoid request logging and run in a trusted environment.

## Replay and session notes

- Each sender session includes a monotonic counter.
- Receivers reject non-increasing counters per sender ephemeral key.
- Nonces are derived from message counters to guarantee nonce uniqueness under a sender session key.
- Forward secrecy is limited to ephemeral sender sessions. Compromise of a current room secret does not recover past session private keys, but it does allow decryption of captured ciphertext for sessions where the attacker can derive the same keys from available material in this v1 design.
