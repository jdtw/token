package token

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"jdtw.dev/token/nonce"
)

func getFreePort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("net.ResolveTCPAddr failed: %v", err)
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		t.Fatalf("net.ListenTCP failed: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type response struct {
	Subject string `json:"subject"`
	Err     string `json:"err"`
}

// startServer runs a server on a free port that attempts to authorize all requests.
// It always responds with code 200 and a JSON-encoded response structure containing the
// result of the authorization. Returns the server's URL.
func startServer(t *testing.T, ks *VerificationKeyset) string {
	t.Helper()
	h := http.NewServeMux()
	nv := nonce.NewMapVerifier(time.Hour)
	h.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		subject, _, err := ks.AuthorizeRequest(r, nv)
		resp := &response{Subject: subject}
		if err != nil {
			resp.Err = err.Error()
		}
		json.NewEncoder(w).Encode(resp)
	})
	addr := fmt.Sprintf("localhost:%d", getFreePort(t))
	s := &http.Server{Addr: addr, Handler: h}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ListenAndServe()
	}()

	ctx := context.Background()
	t.Cleanup(func() {
		s.Shutdown(ctx)
		wg.Wait()
	})

	return fmt.Sprintf("http://%s", addr)
}

type authOpt func(*http.Request) error

func authorize(s *SigningKey) authOpt {
	return func(r *http.Request) error {
		_, err := s.AuthorizeRequest(r, time.Second*5)
		return err
	}
}

func customAuthorization(s string) authOpt {
	return func(r *http.Request) error {
		r.Header.Set("Authorization", s)
		return nil
	}
}

// get does a GET request on the given URL with the given authorization options.
func get(t *testing.T, url string, opts ...authOpt) *response {
	t.Helper()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, opt := range opts {
		if err := opt(req); err != nil {
			t.Fatal(err)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	r := &response{}
	if err := json.Unmarshal(data, r); err != nil {
		t.Fatal(err)
	}
	return r
}

func generateKey(t *testing.T, subject string) (*VerificationKeyset, *SigningKey) {
	t.Helper()
	ks := NewKeyset()
	verifier, signer, err := GenerateKey(subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.Add(verifier); err != nil {
		t.Fatal(err)
	}
	return ks, signer
}

func TestHttp(t *testing.T) {
	ks, priv := generateKey(t, "alice")
	tests := []struct {
		desc    string
		opt     authOpt
		wantErr string
	}{{
		desc: "Success",
		opt:  authorize(priv),
	}, {
		desc:    "Missing header",
		opt:     customAuthorization(""),
		wantErr: "missing Authorization header",
	}, {
		desc:    "Invalid prefix",
		opt:     customAuthorization("Bearer"),
		wantErr: "missing prefix",
	}, {
		desc:    "Invalid proto",
		opt:     customAuthorization("ProtoEd25519 WUVMTE9XIFNVQk1BUklORQ=="),
		wantErr: "cannot parse",
	}, {
		desc: "Untrusted key",
		opt: func() authOpt {
			_, untrusted := generateKey(t, "eve")
			return authorize(untrusted)
		}(),
		wantErr: "unknown key",
	}, {
		desc: "Expired token",
		opt: func() authOpt {
			return func(r *http.Request) error {
				// Issue a token that will expire in 1ms and then sleep for 2ms...
				if _, err := priv.AuthorizeRequest(r, time.Millisecond); err != nil {
					return err
				}
				time.Sleep(time.Millisecond * 2)
				return nil
			}
		}(),
		wantErr: "token expired",
	}, {
		desc: "Invalid resource",
		opt: func() authOpt {
			other, err := http.NewRequest("GET", "http://example.com/some/other/url", nil)
			if err != nil {
				t.Fatal(err)
			}
			return func(r *http.Request) error {
				// Authorize some other request and place it in this header...
				if _, err := priv.AuthorizeRequest(other, time.Second*5); err != nil {
					return err
				}
				r.Header.Set("Authorization", other.Header.Get("Authorization"))
				return nil
			}
		}(),
		wantErr: "invalid resource",
	}}

	url := startServer(t, ks)
	for _, tc := range tests {
		resp := get(t, url, tc.opt)
		if !strings.Contains(resp.Err, tc.wantErr) {
			t.Errorf("Want err containing %q, got %+v", tc.wantErr, resp)
		}
		if tc.wantErr == "" && resp.Subject != "alice" {
			t.Errorf("Expected subject alice, got %+v", resp)
		}
	}
}
