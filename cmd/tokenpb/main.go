package main

import (
	"github.com/alecthomas/kong"
)

var cli struct {
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
