# jdtw.dev/token

[![Go](https://github.com/jdtw/token/actions/workflows/go.yml/badge.svg?branch=main)](https://github.com/jdtw/token/actions/workflows/go.yml)
[![Go Reference](https://pkg.go.dev/badge/jdtw.dev/token.svg)](https://pkg.go.dev/jdtw.dev/token)

The token module provides a protobuf-based authorization token and associated tooling. It is designed to be easy to be used securely with no configuration.

## Example

```
// Generate a key for alice and add the public key to a new keyset.
pub, priv, _ := token.GenerateKey("alice")
keyset := token.NewKeyset()
keyset.Add(pub)
```

Sign a raw token:

```
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

Or, if this is for an HTTP request:

```
// On the client, sign and add to the Authorization header
id, _ := priv.AuthorizeRequest(r, time.Second * 5)
log.Printf("Signed token %s\n", id)

// On the server, verify the token in the Authorization header
nv := nonce.NewMapVerifier(time.Minute) // Prune expired nonces every minute
subject, id, _ := keyset.AuthorizeRequest(r, nv)
log.Printf("Verified token %s, signed by %s\n", id, subject)
```

## Token Format

```
message Token {
  // Required. The resource that this token is authenticating to.
  string resource = 1;

  // Required. The token lifetime.
  google.protobuf.Timestamp not_before = 2;
  google.protobuf.Timestamp not_after = 3;

  // Required. 16 random bytes that uniquely identify this token.
  bytes nonce = 4;
}
```

The token is serialized, signed, and placed in a `SignedToken` message.

```
message SignedToken {
  // Required. The key identifier. The verifier will attempt to find this key in its keyset
  // and use it to verify the token's signature. This is unauthenticated, but if
  // an attacker substitutes a different key ID, the signature will fail to verify.
  string key_id = 1;

  // Required. Ed25519 signarue: sign(priv, header||token)
  bytes signature = 2;

  // Required. A serialized Token proto.
  bytes token = 3;
}
```

The `SignedToken` is serialized and placed in the `Authorization` header using the custom `ProtoEd25519` Scheme.

## Token Signing

The Ed25519 signature is over a constant header (`jdtw.dev/token/v1`) concatenated with the serialized token bytes. Since proto serialization is not canonical, the token is stored in serialized format and deserialized after signature verification.

## Token Verification

The server verifies a token by:

1. Deserializing the `SignedToken` proto.
1. Reading the (unauthenticated) `key_id` from the proto.
1. Looking up `key_id` in the `VerificationKeyset`. If not found, fail.
1. Verifying the Ed25519 signature with the verification key.
1. Deserializing the `Token` proto.
1. Verifying the token expiry: `not_before <= now <= not_after`.
1. Verifying the server `resource` matches the token `resource`.
1. Ensuring that the token's `nonce` hasn't been seen before. (More on this below.)

Verify returns:

1. The subject associated with the verification key.
1. The token's unique ID.

## Token Nonces

`Sign` adds a cryptographically random 16-byte nonce to each token. `Verify` accepts a `nonce.Verifier` interface that should check nonce uniqueness. The nonce is returned from both `Sign` and `Verify` for use as a unique ID that can be used for logging to match client requests and server requests.

The `jdtw.dev/token/nonce` package supplies a `MapVerifier` struct that implements `Verifier`. It uses an in-memory map of seen nonces (pruning them periodically based on expiry).

> **Important:** `MapVerifier` is not suitible for use with sharded servers, since nonces will not by synced between them. This will allow nonce reuse across servers. A better strategy would be to use something like Redis to track nonces for sharded servers.

## Key Format

```
message SigningKey {
  // Optional. The ID of this signing key. Unused in the protocol, but good for humans.
  string id = 1;

  // Required. Ed25519 signing key.
  bytes private_key = 3;
}

message VerificationKey {
  // Required. The ID of this verification key.
  string id = 1;

  // Required. The subject of this key. The token library does not care what the
  // format of the subject string is. It can be an email, hostname, SPIFFE ID, etc.
  string subject = 2;

  // Required. Ed25519 public key bytes.
  bytes public_key = 3;
}

message VerificationKeyset {
  // Map of Key ID to verification key.
  map<string, VerificationKey> keys = 1;
}
```

## Key Distribution

This package provides no control plane for key distribution or registration. My personal use cases require tight control over the keys I issue (and there aren't many of them) so I do it manually with the `tokenpb` tool.

## tokenpb tool

The `tokenpb` tool can be used to generate keys, manage keysets, and sign tokens.

Generate a new key:
```
tokenpb gen-key --subject "${USER}" --pub pub.pb --priv priv.pb
tokenpb dump-pub pub.pb
echo 'Warning, about to dispaly private key material!'
tokenpb dump-priv priv.pb
```

Add the key to a new keyset:
```
tokenpb add-key --pub pub.pb keyset.pb
tokenpb dump-keyset keyset.pb
```

Sign, verify, and parse a token:
```
tokenpb sign-token --resource endpoint priv.pb | \
tokenpb verify-token --resource endpoint keyset.pb | \
tokenpb parse-token
```

Make an HTTP request with a token
```
token=$(sign-token --resource "GET example.com/api" priv.pb)
curl -v -H "Authorization: ${token}" https://example.com/api
```