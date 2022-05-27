package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"jdtw.dev/token"
)

var (
	new     = flag.Bool("new", false, "Create the keyset")
	priv    = flag.String("priv", "", "Private key output location")
	subject = flag.String("subject", "", "Subject for the key")
	dump    = flag.Bool("dump", false, "If true, prints the keyset and/or key as JSON")
)

func main() {
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("Expected exactly one keyset path")
	}
	keyset := flag.Args()[0]

	if *dump {
		bs, err := os.ReadFile(keyset)
		if err != nil {
			log.Fatal(err)
		}
		ks, err := token.UnmarshalVerificationKeyset(bs)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(ks)
		return
	}

	if *new {
		ks := token.NewVerificationKeyset()
		bs, err := ks.Marshal()
		if err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(keyset, bs, 0644); err != nil {
			log.Fatalf("os.WriteFile(%s) failed: %v", keyset, err)
		}
		fmt.Printf("Wrote %s\n", keyset)
		return
	}

	switch {
	case *subject == "":
		log.Fatal("missing 'subject' flag")
	case *priv == "":
		log.Fatal("missing 'priv' flag")
	}

	bs, err := os.ReadFile(keyset)
	if err != nil {
		log.Fatalf("os.Readfile(%s) failed: %v", keyset, err)
	}
	ks, err := token.UnmarshalVerificationKeyset(bs)
	if err != nil {
		log.Fatal(err)
	}

	verifier, signer, err := token.GenerateKey(*subject)
	if err != nil {
		log.Fatal(err)
	}
	if err := ks.Add(verifier); err != nil {
		log.Fatal(err)
	}

	bs, err = ks.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(keyset, bs, 0644); err != nil {
		log.Fatalf("os.WriteFile(%s) failed: %v", keyset, err)
	}
	fmt.Printf("Wrote keyset %s\n", keyset)

	bs, err = signer.Marshal()
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*priv, bs, 0644); err != nil {
		log.Fatalf("os.WriteFile(%s) failed: %v", *priv, err)
	}
	fmt.Printf("Wrote key %s for %s\n", *priv, *subject)
}
