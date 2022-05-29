package main

import (
	"fmt"
	"io/fs"
	"os"

	"jdtw.dev/token"
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

func readKeyset(path string) (*token.VerificationKeyset, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("os.Readfile(%s) failed: %w", path, err)
	}
	return token.UnmarshalVerificationKeyset(bs)
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
