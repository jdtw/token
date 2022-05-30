# token

[![Go](https://github.com/jdtw/token/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/jdtw/token/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/jdtw.dev/token.svg)](https://pkg.go.dev/jdtw.dev/token)

The token module provides a protobuf-based authorization token.

```
	// Generate a key for alice and add the public key to a new keyset.
	pub, priv, _ := token.GenerateKey("alice")
	keyset := token.NewKeyset()
	keyset.Add(pub)

	// Sign a token...
	t, id, _ := priv.Sign(&token.SignOptions{
		Resource: "https://example.com/my/api/endpoint",
		Lifetime: time.Second * 5,
	})
	log.Printf("Signed token %s\n", id)

	// Verify it with the keyset...
	subject, id, _ := keyset.Verify(t, &token.VerifyOptions{
		Resource: "https://example.com/my/api/endpoint",
	})
	log.Printf("Verified token %s, signed by %s\n", id, subject)
  ```