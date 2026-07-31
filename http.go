package token

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"jdtw.dev/token/nonce"
)

// Scheme is the custom authorization scheme for the Authorization header:
// Authorization: ProtoEd25519 <base64 encoded signed token>
const Scheme = "ProtoEd25519 "

// AuthorizeRequest signs a token for the given HTTP request and adds it to the Authorization header.
// Returns the token's unique ID as a hex encoded string.
func (s *SigningKey) AuthorizeRequest(r *http.Request, exp time.Duration) (string, error) {
	opts := &SignOptions{
		Resource: clientResource(r),
		// Allow for some clock skew
		Now:      time.Now(),
		Lifetime: exp,
	}
	token, id, err := s.Sign(opts)
	if err != nil {
		return "", err
	}
	encoded := base64.URLEncoding.EncodeToString(token)
	r.Header.Set("Authorization", Scheme+encoded)
	return id, nil
}

// AuthorizeRequest verifies the token in the Authorization header of the given HTTP request.
func (v *VerificationKeyset) AuthorizeRequest(r *http.Request, skew time.Duration, nv nonce.Verifier) (string, string, error) {
	authz := r.Header.Get("Authorization")
	if authz == "" {
		return "", "", fmt.Errorf("missing Authorization header")
	}
	if !strings.HasPrefix(authz, Scheme) {
		return "", "", fmt.Errorf("authorization header %q missing prefix %q", authz, Scheme)
	}
	encoded := strings.TrimPrefix(authz, Scheme)
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", err
	}
	opts := &VerifyOptions{
		Resource:      serverResource(r),
		NonceVerifier: nv,
		Skew:          skew,
	}
	return v.Verify(decoded, opts)
}

func clientResource(r *http.Request) string {
	path := r.URL.Path
	if path == "" {
		path = "/"
	}
	return fmt.Sprintf("%s %s%s", r.Method, r.URL.Host, path)
}

func serverResource(r *http.Request) string {
	// r.URL.Path is already percent-decoded once by net/http; unescaping
	// it again here would compute a different resource than the client
	// signed (which uses its own, singly-decoded r.URL.Path), rejecting
	// legitimate requests whose path contains a literal '%' followed by
	// hex digits.
	return fmt.Sprintf("%s %s%s", r.Method, r.Host, r.URL.Path)
}
