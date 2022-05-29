package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"jdtw.dev/token"
	"jdtw.dev/token/nonce"
	pb "jdtw.dev/token/proto/token"
)

const (
	// The keyset maintains the +w bit for the owning user so that it may be updated.
	keysetPerm = 0644
	privPerm   = 0400
)

type InitCmd struct {
	Keyset string `arg:"" help:"Path to keyset" type:"path"`
}

type DumpCmd struct {
	JSON   bool   `short:"j" help:"Dump the keyset as JSON"`
	Keyset string `arg:"" help:"Path to keyset" type:"existingfile"`
}

type AddCmd struct {
	Subject  string `short:"s" help:"Subject for the generated key" required:""`
	PrivPath string `short:"p" help:"Path to the private key file" required:"" type:"path"`
	Keyset   string `arg:"" help:"Path to keyset" type:"existingfile"`
}

type RemoveCmd struct {
	ID     string `help:"Key ID to remove" required:""`
	Keyset string `arg:"" help:"Path to keyset" type:"existingfile"`
}

func (i *InitCmd) Run() error {
	ks := token.NewVerificationKeyset()
	if err := writeMarshalable(i.Keyset, ks, keysetPerm); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n", i.Keyset)
	return nil
}

func (d *DumpCmd) Run() error {
	ks, err := readKeyset(d.Keyset)
	if err != nil {
		return err
	}
	if d.JSON {
		return ks.JSON(os.Stdout)
	}
	fmt.Println(ks)
	return nil
}

func (a *AddCmd) Run() error {
	ks, err := readKeyset(a.Keyset)
	if err != nil {
		return err
	}

	pub, priv, err := token.GenerateKey(a.Subject)
	if err != nil {
		return err
	}
	if err := ks.Add(pub); err != nil {
		return err
	}

	if err := writeMarshalable(a.PrivPath, priv, privPerm); err != nil {
		return err
	}
	fmt.Printf("Wrote private key for %q with ID %q to %s\n", pub.Subject(), pub.ID(), a.PrivPath)

	if err := writeMarshalable(a.Keyset, ks, keysetPerm); err != nil {
		return err
	}
	fmt.Printf("Wrote keyset %s\n", a.Keyset)
	return nil
}

func (r *RemoveCmd) Run() error {
	ks, err := readKeyset(r.Keyset)
	if err != nil {
		return err
	}
	ks.Remove(r.ID)
	return writeMarshalable(r.Keyset, ks, keysetPerm)
}

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
