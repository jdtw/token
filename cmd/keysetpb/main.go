package main

import "github.com/alecthomas/kong"

var cli struct {
	Init   InitCmd   `cmd:"" help:"Initialize a new keyset"`
	Dump   DumpCmd   `cmd:"" help:"Dump the keyset as a textproto or JSON"`
	Add    AddCmd    `cmd:"" help:"Generate a new key for the given subject and add it to the keyset"`
	Remove RemoveCmd `cmd:"" help:"Remove a key from the keyset"`
}

func main() {
	ctx := kong.Parse(&cli,
		kong.Name("keysetpb"),
		kong.Description("A tool for managing token proto keysets"),
		kong.UsageOnError())
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
