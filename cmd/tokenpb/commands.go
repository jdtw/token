package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"jdtw.dev/token"
	"jdtw.dev/token/nonce"
	pb "jdtw.dev/token/proto/token"
)

type KeyIDCmd struct {
	Priv string `arg:"" help:"Path to private key" type:"existingfile"`
}

type SignCmd struct {
	Resource string        `short:"r" help:"Token resource" required:""`
	Lifetime time.Duration `short:"l" help:"Token lifetime" default:"1m"`
	Priv     string        `arg:"" help:"Path to private key" type:"existingfile"`
}

type VerifyCmd struct {
	Resource string `short:"r" help:"Token resource" required:""`
	Keyset   string `arg:"" help:"Path to the verification keyset" type:"existingfile"`
}

type ParseCmd struct{}

func (k *KeyIDCmd) Run() error {
	priv, err := readKey(k.Priv)
	if err != nil {
		return err
	}
	fmt.Println(priv.ID())
	return nil
}

func (k *SignCmd) Run() error {
	priv, err := readKey(k.Priv)
	if err != nil {
		return err
	}
	opts := &token.SignOptions{
		Resource: k.Resource,
		Now:      time.Now(),
		Lifetime: k.Lifetime,
	}

	signed, id, err := priv.Sign(opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Signed token with id %s\n", id)
	encoded := base64.URLEncoding.EncodeToString(signed)
	fmt.Println(token.Scheme + encoded)
	return nil
}

func (v *VerifyCmd) Run() error {
	ks, err := readKeyset(v.Keyset)
	if err != nil {
		return err
	}
	all, bs, err := readToken(os.Stdin)
	if err != nil {
		return err
	}
	opts := &token.VerifyOptions{
		Resource:      v.Resource,
		Now:           time.Now(),
		NonceVerifier: noOp,
	}
	subj, id, err := ks.Verify(bs, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Verified token %s signed by %s\n", id, subj)
	_, err = os.Stdout.Write(all)
	return err
}

func (p *ParseCmd) Run() error {
	_, bs, err := readToken(os.Stdin)
	if err != nil {
		return err
	}
	st := &pb.SignedToken{}
	if err := proto.Unmarshal(bs, st); err != nil {
		return err
	}
	t := &pb.Token{}
	if err := proto.Unmarshal(st.Token, t); err != nil {
		return err
	}
	out := &struct {
		KeyId     string    `json:"key_id"`
		Signature []byte    `json:"signature"`
		Token     *pb.Token `json:"token"`
	}{
		KeyId:     st.KeyId,
		Signature: st.Signature,
		Token:     t,
	}
	json.NewEncoder(os.Stdout).Encode(out)
	return nil
}

func readKey(path string) (*token.SigningKey, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("os.Readfile(%s) failed: %w", path, err)
	}
	return token.UnmarshalSigningKey(bs)
}

func readKeyset(path string) (*token.VerificationKeyset, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("os.Readfile(%s) failed: %w", path, err)
	}
	return token.UnmarshalVerificationKeyset(bs)
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
