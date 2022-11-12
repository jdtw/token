package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/proto"
	"jdtw.dev/token"
	pb "jdtw.dev/token/proto/token"
)

type DumpPubCmd struct {
	ID      bool   `help:"Just print the key ID" xor:"id,subject"`
	Subject bool   `help:"Just print the subject" xor:"id,subject"`
	Path    string `arg:"" help:"Path to public key" type:"path" default:"-"`
}

type DumpPrivCmd struct {
	ID   bool   `help:"Just print the key ID"`
	Path string `arg:"" help:"Path to private key" type:"path" default:"-"`
}

type DumpKeysetCmd struct {
	Keyset string `arg:"" help:"Path to keyset" type:"path" default:"-"`
}

type AddCmd struct {
	Pub    string `help:"Path to the public key file" required:"" type:"path"`
	Keyset string `arg:"" help:"Path to keyset" type:"path"`
}

type RemoveCmd struct {
	ID     string `help:"Key ID to remove" required:""`
	Keyset string `arg:"" help:"Path to keyset" type:"path"`
}

type GenCmd struct {
	Subject string `short:"s" help:"Subject for the generated key" required:""`
	Priv    string `help:"Path to private key output" required:"" type:"path"`
	Pub     string `help:"Path to public key output" required:"" type:"path"`
}

type SignCmd struct {
	Resource string        `short:"r" help:"Token resource" required:""`
	Lifetime time.Duration `short:"l" help:"Token lifetime" default:"1m"`
	Priv     string        `arg:"" help:"Path to private key" type:"path" default:"-"`
}

type VerifyCmd struct {
	Resource string `short:"r" help:"Token resource" required:""`
	Keyset   string `arg:"" help:"Path to the verification keyset" type:"path" default:"-"`
}

type ParseCmd struct{}

func (d *DumpPubCmd) Run() error {
	pub, err := readVerificationKey(d.Path)
	if err != nil {
		return err
	}
	switch {
	case d.ID:
		fmt.Println(pub.ID())
	case d.Subject:
		fmt.Println(pub.Subject())
	default:
		fmt.Println(pub)
	}
	return nil
}

func (d *DumpPrivCmd) Run() error {
	priv, err := readKey(d.Path)
	if err != nil {
		return err
	}
	switch {
	case d.ID:
		fmt.Println(priv.ID())
	default:
		fmt.Println(priv)
	}
	return nil
}

func (d *DumpKeysetCmd) Run() error {
	ks, err := readKeyset(d.Keyset)
	if err != nil {
		return err
	}
	fmt.Println(ks)
	return nil
}

func (a *AddCmd) Run() error {
	verb := "Updated"
	ks, err := readKeyset(a.Keyset)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		ks = token.NewKeyset()
		verb = "Created"
	}

	pub, err := readVerificationKey(a.Pub)
	if err != nil {
		return err
	}
	if err := ks.Add(pub); err != nil {
		return err
	}
	if err := writeMarshalable(a.Keyset, ks, keysetPerm); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Added key for %s with ID %s\n", pub.Subject(), pub.ID())
	fmt.Fprintf(os.Stderr, "%s keyset %s\n", verb, a.Keyset)
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

func (n *GenCmd) Run() error {
	pub, priv, err := token.GenerateKey(n.Subject)
	if err != nil {
		return err
	}
	fmt.Println(pub)
	if err := writeMarshalable(n.Pub, pub, pubPerm); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Wrote %s\n", n.Pub)
	if err := writeMarshalable(n.Priv, priv, privPerm); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Wrote %s\n", n.Priv)
	return nil
}

func (k *SignCmd) Run() error {
	priv, err := readKey(k.Priv)
	if err != nil {
		return err
	}
	opts := &token.SignOptions{
		Resource: k.Resource,
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
		Resource: v.Resource,
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
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
