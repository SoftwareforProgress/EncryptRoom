package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fyroc/encryptroom/internal/invite"
	"github.com/fyroc/encryptroom/internal/provision"
)

type buildTarget struct {
	goos   string
	goarch string
	ext    string
}

type createBundleRequest struct {
	ChatName string `json:"chat_name"`
	Password string `json:"password"`
	RelayURL string `json:"relay_url,omitempty"`
}

type artifact struct {
	filename string
	path     string
}

type textArtifact struct {
	filename string
	content  string
}

type apiServer struct {
	projectRoot      string
	defaultRelayURL  string
	corsAllowOrigin  string
	buildTimeout     time.Duration
	targets          []buildTarget
	buildConcurrency chan struct{}
}

func main() {
	listenAddr := flag.String("listen", ":8090", "HTTP listen address")
	projectRoot := flag.String("project-root", ".", "project root used for cross-compiling client binaries")
	defaultRelayURL := flag.String("relay-url", "", "default relay URL injected into invites (required), e.g. tcp://127.0.0.1:8080 or tls://relay.example.com:443")
	corsAllowOrigin := flag.String("cors-allow-origin", "*", "Access-Control-Allow-Origin value")
	buildTimeout := flag.Duration("build-timeout", 120*time.Second, "timeout for one bundle build")
	flag.Parse()

	if strings.TrimSpace(*defaultRelayURL) == "" {
		log.Fatal("-relay-url is required")
	}
	root, err := filepath.Abs(*projectRoot)
	if err != nil {
		log.Fatalf("invalid project root: %v", err)
	}

	srv := &apiServer{
		projectRoot:     root,
		defaultRelayURL: *defaultRelayURL,
		corsAllowOrigin: *corsAllowOrigin,
		buildTimeout:    *buildTimeout,
		targets: []buildTarget{
			{goos: "windows", goarch: "amd64", ext: ".exe"},
			{goos: "darwin", goarch: "arm64", ext: ""},
			{goos: "linux", goarch: "amd64", ext: ""},
		},
		buildConcurrency: make(chan struct{}, 1),
	}
	srv.buildConcurrency <- struct{}{}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", srv.handleHealthz)
	mux.HandleFunc("/api/v1/bundles", srv.handleCreateBundle)

	httpServer := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      5 * time.Minute,
	}

	log.Printf("encryptroom-api listening on %s", *listenAddr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("api server failed: %v", err)
	}
}

func (s *apiServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true}`))
}

func (s *apiServer) handleCreateBundle(w http.ResponseWriter, r *http.Request) {
	s.applyCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	defer r.Body.Close()
	var req createBundleRequest
	if err := decodeJSONBody(r.Body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	cfg, slug, err := provision.BuildInviteConfig(provision.BundleRequest{
		ChatName: req.ChatName,
		Password: req.Password,
		RelayURL: req.RelayURL,
	}, s.defaultRelayURL)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), s.buildTimeout)
	defer cancel()

	bundle, bundleName, err := s.generateBundle(ctx, cfg, slug)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			status = http.StatusGatewayTimeout
		}
		writeJSONError(w, status, "failed to create binary bundle")
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", bundleName))
	w.Header().Set("X-EncryptRoom-Room-ID", cfg.RoomID)
	w.Header().Set("X-EncryptRoom-Chat", slug)
	if cfg.RoomName != "" {
		w.Header().Set("X-EncryptRoom-Room-Name", cfg.RoomName)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

func (s *apiServer) generateBundle(ctx context.Context, cfg invite.Config, slug string) ([]byte, string, error) {
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case <-s.buildConcurrency:
		defer func() { s.buildConcurrency <- struct{}{} }()
	}

	tmpDir, err := os.MkdirTemp("", "encryptroom-bundle-")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(tmpDir)

	cacheDir := filepath.Join(tmpDir, "go-build-cache")
	modCacheDir := filepath.Join(tmpDir, "go-mod-cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return nil, "", err
	}
	if err := os.MkdirAll(modCacheDir, 0o700); err != nil {
		return nil, "", err
	}

	artifacts := make([]artifact, 0, len(s.targets))
	for _, target := range s.targets {
		basePath := filepath.Join(tmpDir, fmt.Sprintf("encryptroom-base-%s-%s%s", target.goos, target.goarch, target.ext))
		if err := buildClientBinary(ctx, s.projectRoot, cacheDir, modCacheDir, target, basePath); err != nil {
			return nil, "", err
		}

		filename := fmt.Sprintf("encryptroom-%s-%s-%s%s", slug, target.goos, target.goarch, target.ext)
		embeddedPath := filepath.Join(tmpDir, filename)
		if err := invite.WriteInviteToBinary(basePath, embeddedPath, cfg); err != nil {
			return nil, "", err
		}
		artifacts = append(artifacts, artifact{filename: filename, path: embeddedPath})
	}

	bundleName := fmt.Sprintf("encryptroom-%s-%s-bundle.zip", slug, cfg.RoomID[:8])
	zipBytes, err := createZip(artifacts, buildInstructionFiles(artifacts, cfg))
	if err != nil {
		return nil, "", err
	}
	return zipBytes, bundleName, nil
}

func buildClientBinary(ctx context.Context, projectRoot, cacheDir, modCacheDir string, target buildTarget, outPath string) error {
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", outPath, "./cmd/encryptroom")
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(),
		"GOOS="+target.goos,
		"GOARCH="+target.goarch,
		"CGO_ENABLED=0",
		"GOCACHE="+cacheDir,
		"GOMODCACHE="+modCacheDir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build failed for %s/%s: %w: %s", target.goos, target.goarch, err, trimBuildOutput(out))
	}
	return nil
}

func createZip(artifacts []artifact, textArtifacts []textArtifact) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	for _, artifact := range artifacts {
		w, err := zw.Create(artifact.filename)
		if err != nil {
			_ = zw.Close()
			return nil, err
		}

		f, err := os.Open(artifact.path)
		if err != nil {
			_ = zw.Close()
			return nil, err
		}
		_, copyErr := io.Copy(w, f)
		closeErr := f.Close()
		if copyErr != nil {
			_ = zw.Close()
			return nil, copyErr
		}
		if closeErr != nil {
			_ = zw.Close()
			return nil, closeErr
		}
	}
	for _, textFile := range textArtifacts {
		w, err := zw.Create(textFile.filename)
		if err != nil {
			_ = zw.Close()
			return nil, err
		}
		if _, err := io.WriteString(w, textFile.content); err != nil {
			_ = zw.Close()
			return nil, err
		}
	}

	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func buildInstructionFiles(artifacts []artifact, cfg invite.Config) []textArtifact {
	findBinary := func(suffix string) string {
		for _, a := range artifacts {
			if strings.Contains(a.filename, suffix) {
				return a.filename
			}
		}
		return ""
	}

	windowsBinary := findBinary("-windows-amd64.exe")
	macosBinary := findBinary("-darwin-arm64")
	linuxBinary := findBinary("-linux-amd64")

	roomDisplay := cfg.RoomID
	if cfg.RoomName != "" {
		roomDisplay = cfg.RoomName + " (" + cfg.RoomID + ")"
	}
	passwordNote := "No room password is required by this invite."
	if cfg.PasswordRequired {
		passwordNote = "When prompted, enter the room password that was set when this bundle was created."
	}

	common := "Room: " + roomDisplay + "\n" +
		"Relay: " + cfg.RelayURL + "\n\n" +
		"Startup prompts:\n" +
		"1. Display name\n" +
		"2. Room password (if required)\n\n" +
		passwordNote + "\n\n"

	windowsInstructions := common +
		"Windows (PowerShell):\n" +
		"  .\\" + windowsBinary + "\n\n" +
		"Windows (cmd.exe):\n" +
		"  " + windowsBinary + "\n"

	macosInstructions := common +
		"macOS (Terminal):\n" +
		"  chmod +x " + macosBinary + "\n" +
		"  ./" + macosBinary + "\n"

	linuxInstructions := common +
		"Linux (terminal):\n" +
		"  chmod +x " + linuxBinary + "\n" +
		"  ./" + linuxBinary + "\n"

	readme := "EncryptRoom bundle contents:\n\n" +
		"- " + windowsBinary + " (Windows)\n" +
		"- " + macosBinary + " (macOS)\n" +
		"- " + linuxBinary + " (Linux)\n" +
		"- RUN-WINDOWS.txt\n" +
		"- RUN-MACOS.txt\n" +
		"- RUN-LINUX.txt\n\n" +
		"Each binary contains the embedded invite for this room.\n"

	return []textArtifact{
		{filename: "README.txt", content: readme},
		{filename: "RUN-WINDOWS.txt", content: windowsInstructions},
		{filename: "RUN-MACOS.txt", content: macosInstructions},
		{filename: "RUN-LINUX.txt", content: linuxInstructions},
	}
}

func decodeJSONBody(r io.Reader, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r, 8*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("invalid JSON request: trailing data")
	}
	return nil
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (s *apiServer) applyCORS(w http.ResponseWriter) {
	if s.corsAllowOrigin == "" {
		return
	}
	w.Header().Set("Access-Control-Allow-Origin", s.corsAllowOrigin)
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func trimBuildOutput(out []byte) string {
	const max = 400
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "no build output"
	}
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
