package mcpclient

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"

	"github.com/go-authgate/agent-scanner/internal/models"
)

type stdioTransport struct {
	server *models.StdioServer
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	recvCh chan *JSONRPCMessage
	mu     sync.Mutex
	lines  []string
}

// NewStdioTransport creates a transport that communicates via subprocess stdio.
func NewStdioTransport(server *models.StdioServer) Transport {
	return &stdioTransport{
		server: server,
		recvCh: make(chan *JSONRPCMessage, 64),
	}
}

func (t *stdioTransport) Connect(ctx context.Context) error {
	command := t.server.Command
	args := t.server.Args

	// Resolve command path
	path, err := exec.LookPath(command)
	if err != nil {
		return fmt.Errorf("command not found: %s: %w", command, err)
	}

	t.cmd = exec.CommandContext(ctx, path, args...)

	// Set environment variables
	if len(t.server.Env) > 0 {
		t.cmd.Env = t.cmd.Environ()
		for k, v := range t.server.Env {
			t.cmd.Env = append(t.cmd.Env, k+"="+v)
		}
	}

	t.stdin, err = t.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	t.stdout, err = t.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	t.stderr, err = t.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := t.cmd.Start(); err != nil {
		return fmt.Errorf("start process: %w", err)
	}

	// Read stdout in background
	go t.readStdout()
	// Capture stderr in background
	go t.readStderr()

	slog.Debug("stdio transport connected", "command", command, "args", sanitizeArgs(args))
	return nil
}

func (t *stdioTransport) readStdout() {
	defer close(t.recvCh)
	scanner := bufio.NewScanner(t.stdout)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024) // 1MB buffer
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var msg JSONRPCMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			slog.Debug("failed to parse JSON-RPC message", "error", err, "line", line)
			continue
		}
		t.recvCh <- &msg
	}
}

func (t *stdioTransport) readStderr() {
	scanner := bufio.NewScanner(t.stderr)
	for scanner.Scan() {
		line := scanner.Text()
		t.mu.Lock()
		t.lines = append(t.lines, line)
		t.mu.Unlock()
		slog.Debug("server stderr", "line", line)
	}
}

// GetStderr returns a copy of the captured stderr lines.
func (t *stdioTransport) GetStderr() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, len(t.lines))
	copy(out, t.lines)
	return out
}

func (t *stdioTransport) Send(_ context.Context, msg *JSONRPCMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = t.stdin.Write(data)
	return err
}

func (t *stdioTransport) Receive() <-chan *JSONRPCMessage {
	return t.recvCh
}

func (t *stdioTransport) Close() error {
	if t.stdin != nil {
		t.stdin.Close()
	}
	if t.cmd != nil && t.cmd.Process != nil {
		_ = t.cmd.Process.Kill()
		_ = t.cmd.Wait()
	}
	return nil
}
