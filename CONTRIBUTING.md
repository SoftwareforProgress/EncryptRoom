# Contributing

Thanks for contributing to EncryptRoom.

## Local development

- Install Go (1.22+ recommended).
- Run tests: `go test ./...`
- Run lint/static checks: `go vet ./...`

## Pull requests

- Keep PRs focused and small.
- Add tests for behavior changes.
- Document security-relevant changes in `README.md` and `SECURITY.md`.

## Security

- Do not add server-side message storage.
- Do not log room secrets, payloads, or user identifiers.
- Do not replace audited crypto primitives with custom algorithms.
