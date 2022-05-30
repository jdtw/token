package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"jdtw.dev/token"
	"jdtw.dev/token/nonce"
)

func readAll(path string) ([]byte, error) {
	f := os.Stdin
	if path != "-" {
		var err error
		f, err = os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
	}
	return io.ReadAll(f)
}

type Marshalable interface {
	Marshal() ([]byte, error)
}

func writeMarshalable(path string, m Marshalable, perm fs.FileMode) error {
	bs, err := m.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, bs, perm); err != nil {
		return fmt.Errorf("os.WriteFile(%s) failed: %w", path, err)
	}
	return nil
}

func readKey(path string) (*token.SigningKey, error) {
	bs, err := readAll(path)
	if err != nil {
		return nil, err
	}
	return token.UnmarshalSigningKey(bs)
}

func readKeyset(path string) (*token.VerificationKeyset, error) {
	bs, err := readAll(path)
	if err != nil {
		return nil, err
	}
	return token.UnmarshalVerificationKeyset(bs)
}

func readVerificationKey(path string) (*token.VerificationKey, error) {
	bs, err := readAll(path)
	if err != nil {
		return nil, err
	}
	return token.UnmarshalVerificationKey(bs)
}

func readToken(r io.Reader) ([]byte, []byte, error) {
	bs, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	encoded := strings.TrimPrefix(string(bs), token.Scheme)
	decoded, err := base64.URLEncoding.DecodeString(encoded)
	return bs, decoded, err
}

type noOpNonceVerifier struct{}

var noOp nonce.Verifier = noOpNonceVerifier{}

func (n noOpNonceVerifier) Verify(nonce []byte, expires time.Time) error {
	return nil
}
