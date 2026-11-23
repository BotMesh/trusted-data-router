// trusted-router-tunnel is a private process adapter for unmodified Chisel.
// Rust owns authorization and the public listener. Secrets arrive over stdin,
// never argv, environment variables, files, or application traffic.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	chclient "github.com/jpillora/chisel/client"
	chserver "github.com/jpillora/chisel/server"
)

const maxLine = 32768
const sentinel = "router-deny-all"

type config struct {
	Mode        string `json:"mode"`
	Listen      string `json:"listen,omitempty"`
	Server      string `json:"server,omitempty"`
	Token       string `json:"token,omitempty"`
	Auth        string `json:"auth,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Target      string `json:"target,omitempty"`
	Reverse     bool   `json:"reverse,omitempty"`
	CA          string `json:"ca,omitempty"`
}

type command struct {
	Op       string `json:"op"`
	User     string `json:"user"`
	Password string `json:"password,omitempty"`
	Address  string `json:"address,omitempty"`
	Reverse  bool   `json:"reverse,omitempty"`
}

func decode(line []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(line))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing input")
	}
	return nil
}

func loopback(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return false
	}
	// Chisel remotes do not support port zero. ResolveTCPAddr validates range.
	a, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(host, port))
	return err == nil && a.Port > 0 && fmt.Sprint(a.Port) == port
}

func credential(value string) bool {
	return len(value) >= 32 && len(value) <= 128 && regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(value)
}

func clientConfig(c config) (*chclient.Config, error) {
	u, err := url.Parse(c.Server)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback())) ||
		!loopback(c.Listen) || !loopback(c.Target) || len(c.Token) == 0 || len(c.Token) > 8192 || strings.ContainsAny(c.Token, "\r\n") {
		return nil, errors.New("invalid client configuration")
	}
	auth := strings.Split(c.Auth, ":")
	fingerprint, err := base64.StdEncoding.DecodeString(c.Fingerprint)
	if len(auth) != 2 || !credential(auth[0]) || !credential(auth[1]) || err != nil || len(fingerprint) != 32 {
		return nil, errors.New("invalid credentials")
	}
	remote := c.Listen + ":" + c.Target
	if c.Reverse {
		remote = "R:" + remote
	}
	return &chclient.Config{
		Server: c.Server, Auth: c.Auth, Fingerprint: c.Fingerprint,
		Headers: http.Header{"Authorization": {"Bearer " + c.Token}},
		Remotes: []string{remote}, KeepAlive: 25 * time.Second,
		// Rust must obtain a fresh lease before reconnecting. Never retry a
		// spent lease or replay application requests inside this process.
		MaxRetryCount: 0, TLS: chclient.TLSConfig{CA: c.CA},
	}, nil
}

func newServer(listen string) (*chserver.Server, error) {
	if !loopback(listen) {
		return nil, errors.New("invalid server listener")
	}
	s, err := chserver.NewServer(&chserver.Config{Reverse: true, KeepAlive: 25 * time.Second})
	if err != nil {
		return nil, err
	}
	s.Info = false
	// Upstream deliberately disables authentication when the user index is
	// empty. This permanent, secret, no-address user keeps it fail-closed.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := s.AddUser(sentinel, hex.EncodeToString(secret)); err != nil {
		return nil, err
	}
	host, port, _ := net.SplitHostPort(listen)
	if err := s.Start(host, port); err != nil {
		return nil, err
	}
	return s, nil
}

func apply(s *chserver.Server, users map[string]bool, c command) error {
	if !credential(c.User) {
		return errors.New("invalid user")
	}
	switch c.Op {
	case "add":
		if users[c.User] || len(users) >= 1024 || !credential(c.Password) || !loopback(c.Address) {
			return errors.New("invalid lease")
		}
		address := c.Address
		if c.Reverse {
			address = "R:" + address
		}
		if err := s.AddUser(c.User, c.Password, "^"+regexp.QuoteMeta(address)+"$"); err != nil {
			return err
		}
		users[c.User] = true
	case "remove":
		if c.Password != "" || c.Address != "" || c.Reverse {
			return errors.New("invalid removal")
		}
		s.DeleteUser(c.User)
		delete(users, c.User)
	default:
		return errors.New("invalid operation")
	}
	return nil
}

func run(ctx context.Context, input io.Reader, output io.Writer) error {
	lines := bufio.NewScanner(input)
	lines.Buffer(make([]byte, 4096), maxLine)
	var c config
	if !lines.Scan() || decode(lines.Bytes(), &c) != nil {
		return errors.New("invalid configuration")
	}
	out := json.NewEncoder(output)
	switch c.Mode {
	case "server":
		if c.Server != "" || c.Token != "" || c.Auth != "" || c.Fingerprint != "" || c.Target != "" || c.Reverse || c.CA != "" {
			return errors.New("invalid server configuration")
		}
		s, err := newServer(c.Listen)
		if err != nil {
			return err
		}
		defer s.Close()
		if err := out.Encode(map[string]any{"ok": true, "fingerprint": s.GetFingerprint()}); err != nil {
			return err
		}
		users := make(map[string]bool)
		for lines.Scan() {
			var cmd command
			ok := decode(lines.Bytes(), &cmd) == nil && apply(s, users, cmd) == nil
			if err := out.Encode(map[string]bool{"ok": ok}); err != nil {
				return err
			}
		}
		return lines.Err()
	case "client":
		cc, err := clientConfig(c)
		if err != nil {
			return err
		}
		client, err := chclient.NewClient(cc)
		if err != nil {
			return err
		}
		client.Info = false
		if err := client.Start(ctx); err != nil {
			return err
		}
		defer client.Close()
		// Parent death closes stdin. Do not leave reconnecting orphans behind.
		go func() { lines.Scan(); client.Close() }()
		ready, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		connected := make(chan bool, 1)
		finished := make(chan error, 1)
		go func() { connected <- client.Ready(ready) }()
		go func() { finished <- client.Wait() }()
		select {
		case ok := <-connected:
			if !ok {
				return errors.New("connection failed")
			}
		case <-finished:
			return errors.New("connection failed")
		}
		if err := out.Encode(map[string]bool{"ok": true}); err != nil {
			return err
		}
		return <-finished
	default:
		return errors.New("invalid mode")
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); os.Stdin.Close() }()
	if err := run(ctx, os.Stdin, os.Stdout); err != nil {
		// Errors from upstream may contain addresses or user-controlled input.
		fmt.Fprintln(os.Stderr, "trusted-router-tunnel: operation failed")
		os.Exit(1)
	}
}
