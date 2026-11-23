package main

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	chclient "github.com/jpillora/chisel/client"
	chshare "github.com/jpillora/chisel/share"
	"github.com/jpillora/chisel/share/ccrypto"
	"github.com/jpillora/chisel/share/cnet"
	"github.com/jpillora/chisel/share/settings"
	"golang.org/x/crypto/ssh"
)

func unused(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func TestAuthenticationAndChannelIsolation(t *testing.T) {
	address := unused(t)
	s, err := newServer(address)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	user, password := strings.Repeat("a", 32), strings.Repeat("b", 32)
	dial := func() (ssh.Conn, error) {
		d := websocket.Dialer{Subprotocols: []string{chshare.ProtocolVersion}, HandshakeTimeout: time.Second}
		ws, _, err := d.Dial("ws://"+address, nil)
		if err != nil {
			return nil, err
		}
		ws.UnderlyingConn().SetDeadline(time.Now().Add(3 * time.Second))
		conn, channels, requests, err := ssh.NewClientConn(cnet.NewWebSocketConn(ws), "", &ssh.ClientConfig{
			User: user, Auth: []ssh.AuthMethod{ssh.Password(password)},
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				if ccrypto.FingerprintKey(key) != s.GetFingerprint() {
					return io.ErrUnexpectedEOF
				}
				return nil
			},
		})
		if err != nil {
			ws.Close()
			return nil, err
		}
		go ssh.DiscardRequests(requests)
		go func() {
			for channel := range channels {
				channel.Reject(ssh.Prohibited, "unused")
			}
		}()
		return conn, nil
	}
	// Empty tenant table must not trigger upstream's anonymous mode.
	if conn, err := dial(); err == nil {
		conn.Close()
		t.Fatal("anonymous access before enrollment")
	}
	users := make(map[string]bool)
	allowed := unused(t)
	if err := apply(s, users, command{Op: "add", User: user, Password: password, Address: allowed, Reverse: true}); err != nil {
		t.Fatal(err)
	}
	conn, err := dial()
	if err != nil {
		t.Fatal(err)
	}
	remote, _ := settings.DecodeRemote("R:" + unused(t) + ":127.0.0.1:9")
	ok, _, err := conn.SendRequest("config", true, settings.EncodeConfig(settings.Config{Remotes: settings.Remotes{remote}}))
	conn.Close()
	if err != nil || ok {
		t.Fatalf("another route's reverse listener accepted: ok=%v err=%v", ok, err)
	}
	conn, err = dial()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ok, _, err = conn.SendRequest("config", true, settings.EncodeConfig(settings.Config{}))
	if err != nil || !ok {
		t.Fatal("cannot establish restricted session")
	}
	for _, destination := range []string{allowed, "127.0.0.1:22", "socks", allowed + "/udp"} {
		channel, _, err := conn.OpenChannel("chisel", []byte(destination))
		if err == nil {
			channel.Close()
			t.Fatalf("reverse credential allowed forward channel %s", destination)
		}
	}
	if err := apply(s, users, command{Op: "remove", User: user}); err != nil {
		t.Fatal(err)
	}
	if conn, err := dial(); err == nil {
		conn.Close()
		t.Fatal("anonymous access after last lease removal")
	}
}

func TestVerifiedWSSHeadersAndHalfClose(t *testing.T) {
	address := unused(t)
	s, err := newServer(address)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	upstream, _ := url.Parse("http://" + address)
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	front := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-capability" {
			w.WriteHeader(401)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer front.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: front.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	go func() {
		conn, err := backend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		conn.Write([]byte("server-first\n"))
		body, err := io.ReadAll(conn)
		if err == nil {
			conn.Write(body)
		}
	}()
	listen := unused(t)
	user, password := strings.Repeat("c", 32), strings.Repeat("d", 32)
	if err := apply(s, make(map[string]bool), command{Op: "add", User: user, Password: password, Address: listen, Reverse: true}); err != nil {
		t.Fatal(err)
	}
	conf := config{Mode: "client", Server: front.URL, Token: "test-capability", Auth: user + ":" + password, Fingerprint: s.GetFingerprint(), Listen: listen, Target: backend.Addr().String(), Reverse: true, CA: ca}
	cc, err := clientConfig(conf)
	if err != nil {
		t.Fatal(err)
	}
	client, err := chclient.NewClient(cc)
	if err != nil {
		t.Fatal(err)
	}
	client.Info = false
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if !client.Ready(ctx) {
		t.Fatal("verified WSS connection failed")
	}
	var conn *net.TCPConn
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		conn, err = net.DialTCP("tcp", nil, mustTCP(t, listen))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	banner := make([]byte, len("server-first\n"))
	if _, err := io.ReadFull(conn, banner); err != nil || string(banner) != "server-first\n" {
		t.Fatal("server-first data failed", err)
	}
	payload := strings.Repeat("\x00\xffhalf-close", 32768)
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil || string(reply) != payload {
		t.Fatal("half-close response failed", err, len(reply))
	}
	// Verify the public TLS boundary actually rejects an unknown CA.
	_, err = tls.Dial("tcp", strings.TrimPrefix(front.URL, "https://"), &tls.Config{MinVersion: tls.VersionTLS12})
	if err == nil {
		t.Fatal("unknown TLS CA accepted")
	}
}

func mustTCP(t *testing.T, address string) *net.TCPAddr {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

func TestRejectUnsafeConfiguration(t *testing.T) {
	base := config{Server: "https://router.example/route", Token: "capability", Auth: strings.Repeat("a", 32) + ":" + strings.Repeat("b", 32), Fingerprint: strings.Repeat("A", 43) + "=", Listen: "127.0.0.1:8080", Target: "127.0.0.1:8081", Reverse: true}
	for _, change := range []func(*config){
		func(c *config) { c.Server = "http://router.example" },
		func(c *config) { c.Server = "https://user:pass@router.example" },
		func(c *config) { c.Server += "?token=secret" },
		func(c *config) { c.Listen = "0.0.0.0:80" },
		func(c *config) { c.Target = "192.168.1.1:80" },
		func(c *config) { c.Target = "localhost:80" },
		func(c *config) { c.Token = "secret\r\nInjected: yes" },
		func(c *config) { c.Fingerprint = "" },
	} {
		c := base
		change(&c)
		if _, err := clientConfig(c); err == nil {
			t.Fatal("unsafe configuration accepted")
		}
	}
}
