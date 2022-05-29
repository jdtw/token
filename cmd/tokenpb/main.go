package main

import (
	"github.com/alecthomas/kong"
)

var cli struct {
	Keyset struct {
		Init   InitCmd   `cmd:"" help:"Initialize a new keyset"`
		Dump   DumpCmd   `cmd:"" help:"Dump the keyset as a textproto or JSON"`
		Add    AddCmd    `cmd:"" help:"Generate a new key for the given subject and add it to the keyset"`
		Remove RemoveCmd `cmd:"" help:"Remove a key from the keyset"`
	} `cmd:"" help:"Keyset management operations"`
	KeyID  KeyIDCmd  `cmd:"" help:"Print the key ID for the given signing key"`
	Sign   SignCmd   `cmd:"" help:"Sign a token"`
	Verify VerifyCmd `cmd:"" help:"Verify a token"`
	Parse  ParseCmd  `cmd:"" help:"Parse a signed proto token"`
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Name("tokenpb"),
		kong.UsageOnError())
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
