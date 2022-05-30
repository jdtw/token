package main

import "github.com/alecthomas/kong"

const (
	// The keyset maintains the +w bit for the owning user so that it may be updated.
	keysetPerm = 0644
	privPerm   = 0400
	pubPerm    = 0444
)

var cli struct {
	DumpKeyset  DumpKeysetCmd `cmd:"" help:"Dump a keyset"`
	DumpPub     DumpPubCmd    `cmd:"" help:"Dump public key"`
	DumpPriv    DumpPrivCmd   `cmd:"" help:"Dump private key"`
	AddKey      AddCmd        `cmd:"" help:"Add a verification key to the keyset"`
	RemoveKey   RemoveCmd     `cmd:"" help:"Remove a key from the keyset"`
	GenKey      GenCmd        `cmd:"" help:"Generate a new key for the given subject"`
	SignToken   SignCmd       `cmd:"" help:"Sign a token"`
	VerifyToken VerifyCmd     `cmd:"" help:"Verify a token"`
	ParseToken  ParseCmd      `cmd:"" help:"Parse a signed proto token from stdin"`
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Name("tokenpb"),
		kong.UsageOnError())
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
