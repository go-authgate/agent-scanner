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

	"github.com/go-authgate/agent-scanner/internal/models"
)

type stdioTransport struct {
	server *models.StdioServer
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
	recvCh chan *JSONRPCMessage
	Stderr []string
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

	// Resolve command path (with fallback to common install dirs)
	path, err := resolveCommand(command)
	if err != nil {
		return fmt.Errorf("resolve command: %w", err)
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

	slog.Debug("stdio transport connected", "command", command, "args", args)
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
		t.Stderr = append(t.Stderr, line)
		slog.Debug("server stderr", "line", line)
	}
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
