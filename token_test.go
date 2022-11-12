package token

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/testing/protocmp"
	"jdtw.dev/token/nonce"
	pb "jdtw.dev/token/proto/token"
)

func generateKeys(t *testing.T, subjects ...string) (*VerificationKeyset, map[string]*SigningKey) {
	t.Helper()
	ks := NewKeyset()
	signers := make(map[string]*SigningKey)
	for _, sub := range subjects {
		verifier, signer, err := GenerateKey(sub)
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.Add(verifier); err != nil {
			t.Fatal(err)
		}
		signers[sub] = signer
	}
	return ks, signers
}

type fakeNonceVerifier struct {
	err error
}

var _ nonce.Verifier = &fakeNonceVerifier{}

func (f *fakeNonceVerifier) Verify(nonce []byte, expires time.Time) error {
	return f.err
}

func unmarshalToken(t *testing.T, bytes []byte) (*pb.SignedToken, *pb.Token) {
	t.Helper()
	signed := &pb.SignedToken{}
	if err := proto.Unmarshal(bytes, signed); err != nil {
		t.Fatal(err)
	}
	token := &pb.Token{}
	if err := proto.Unmarshal(signed.Token, token); err != nil {
		t.Fatal(err)
	}
	return signed, token
}

func marshal(t *testing.T, m protoreflect.ProtoMessage) []byte {
	t.Helper()
	bytes, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return bytes
}

func TestGenerateKey(t *testing.T) {
	v, s, err := GenerateKey("alice")
	if err != nil {
		t.Fatal(err)
	}
	if v.Subject() != "alice" {
		t.Errorf("Subject() = %q, want \"alice\"", v.Subject())
	}
	if v.ID() != s.ID() {
		t.Errorf("Public key ID %q doesn't match private key ID %q", v.ID(), s.key.Id)
	}
	if v.ID() == "" {
		t.Errorf("Empty key ID")
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	pub, priv, err := GenerateKey("bob")
	if err != nil {
		t.Fatal(err)
	}

	// Marshal and unmarshal the public key...
	t.Run("pub", func(t *testing.T) {
		bs, err := pub.Marshal()
		if err != nil {
			t.Fatalf("Failed to marshal public key: %v", err)
		}
		upub, err := UnmarshalVerificationKey(bs)
		if err != nil {
			t.Fatalf("UnmarshalVerificationKey failed: %v", err)
		}
		if diff := cmp.Diff(pub.key, upub.key, protocmp.Transform()); diff != "" {
			t.Fatalf("Pub key mismatch (-want +got):\n%s", diff)
		}
	})

	// Marshal and unmarshal the private key...
	t.Run("priv", func(t *testing.T) {
		bs, err := priv.Marshal()
		if err != nil {
			t.Fatalf("Failed to marshal private key: %v", err)
		}
		upriv, err := UnmarshalSigningKey(bs)
		if err != nil {
			t.Fatalf("UnmarshalSigningKey failed: %v", err)
		}
		if diff := cmp.Diff(priv.key, upriv.key, protocmp.Transform()); diff != "" {
			t.Fatalf("Priv key mismatch (-want +got):\n%s", diff)
		}
	})

	// Marshal and unmarshal a keyset...
	t.Run("keyset", func(t *testing.T) {
		ks := NewKeyset()
		if err := ks.Add(pub); err != nil {
			t.Fatalf("ks.Add failed: %v", err)
		}
		bs, err := ks.Marshal()
		if err != nil {
			t.Fatalf("Failed to marshal keyset: %v", err)
		}
		uks, err := UnmarshalKeyset(bs)
		if err != nil {
			t.Fatalf("Failed to unmarshal keyset: %v", err)
		}
		if diff := cmp.Diff(ks.keys, uks.keys, protocmp.Transform()); diff != "" {
			t.Fatalf("Keyset mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestInvalidUnmarshal(t *testing.T) {
	pub, priv, err := GenerateKey("alice")
	if err != nil {
		t.Fatal(err)
	}

	pubBytes, err := pub.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	privBytes, err := priv.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := UnmarshalVerificationKey(privBytes); err == nil { // if NO error
		t.Errorf("Unmarshalling a public key as a private key should fail.")
	}

	if _, err := UnmarshalSigningKey(pubBytes); err == nil { // if NO error
		t.Errorf("Unmarshalling a private key as a public key should fail.")
	}
}

func TestSigningKeyUnmarshalFailure(t *testing.T) {
	tests := []struct {
		key *pb.SigningKey
		err error
	}{{
		key: &pb.SigningKey{
			Id:         "",
			PrivateKey: make([]byte, ed25519.PrivateKeySize),
		},
		err: ErrMissingID,
	}, {
		key: &pb.SigningKey{
			Id:         "id",
			PrivateKey: nil,
		},
		err: ErrInvaidKeyLen,
	}}
	for _, tc := range tests {
		bs, err := proto.Marshal(tc.key)
		if err != nil {
			t.Fatalf("proto.Marshal(%v) failed: %v", tc.key, err)
		}
		if _, err := UnmarshalSigningKey(bs); !errors.Is(err, tc.err) {
			t.Errorf("Unmarshel %v = %v, want err %v", err, tc.key, tc.err)
		}
	}
}

func TestVerificationKeyUnmarshalFailure(t *testing.T) {
	tests := []struct {
		key *pb.VerificationKey
		err error
	}{{
		key: &pb.VerificationKey{
			Subject:   "",
			Id:        "id",
			PublicKey: make([]byte, ed25519.PublicKeySize),
		},
		err: ErrMissingSubject,
	}, {
		key: &pb.VerificationKey{
			Subject:   "carol",
			Id:        "",
			PublicKey: make([]byte, ed25519.PublicKeySize),
		},
		err: ErrMissingID,
	}, {
		key: &pb.VerificationKey{
			Subject:   "eve",
			Id:        "eve's key",
			PublicKey: nil,
		},
		err: ErrInvaidKeyLen,
	}}
	for _, tc := range tests {
		bs, err := proto.Marshal(tc.key)
		if err != nil {
			t.Fatalf("proto.Marshal(%v) failed: %v", tc.key, err)
		}
		if _, err := UnmarshalVerificationKey(bs); !errors.Is(err, tc.err) {
			t.Errorf("Unmarshel %v = %v, want err %v", err, tc.key, tc.err)
		}
	}
}

func TestVerifyWrongKey(t *testing.T) {
	verifier, signers := generateKeys(t, "alice", "bob")
	sopts := &SignOptions{
		Resource: "foo",
		Now:      time.Now(),
		Lifetime: time.Minute,
	}
	vopts := &VerifyOptions{
		Resource:      sopts.Resource,
		Now:           sopts.Now,
		NonceVerifier: nonce.NewMapVerifier(time.Hour),
	}

	// Sign with Alice's key...
	signed, _, err := signers["alice"].Sign(sopts)
	if err != nil {
		t.Fatal(err)
	}

	// Remove Alice's key from the map...
	verifier.Remove(signers["alice"].ID())

	// Verification should fail.
	if _, _, err := verifier.Verify(signed, vopts); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Verify(%v) = %v, want %v", vopts, err, ErrSignature)
	}

	// Replace the Key ID with Bob's key...
	signedProto, _ := unmarshalToken(t, signed)
	signedProto.KeyId = signers["bob"].key.Id
	signed = marshal(t, signedProto)

	// Verification should fail.
	if _, _, err := verifier.Verify(signed, vopts); !errors.Is(err, ErrSignature) {
		t.Errorf("Verify(%v) = %v, want %v", vopts, err, ErrSignature)
	}
}

func TestSignVerify(t *testing.T) {
	now := time.Now()
	verifier, signers := generateKeys(t, "test")
	signer := signers["test"]
	tests := []struct {
		desc    string
		sign    *SignOptions
		verify  *VerifyOptions
		wantErr error
	}{{
		desc: "success",
		sign: &SignOptions{
			Resource: "foo",
			Now:      now,
			Lifetime: time.Second,
		},
		verify: &VerifyOptions{
			Resource:      "foo",
			Now:           now,
			NonceVerifier: &fakeNonceVerifier{},
		},
	}, {
		desc: "wrong resource fails",
		sign: &SignOptions{
			Resource: "foo",
			Now:      now,
			Lifetime: time.Second,
		},
		verify: &VerifyOptions{
			Resource:      "bar",
			Now:           now,
			NonceVerifier: &fakeNonceVerifier{},
		},
		wantErr: ErrResource,
	}, {
		desc: "not valid yet",
		sign: &SignOptions{
			Resource: "foo",
			Now:      now.Add(time.Second),
			Lifetime: time.Second,
		},
		verify: &VerifyOptions{
			Resource:      "foo",
			Now:           now,
			NonceVerifier: &fakeNonceVerifier{},
		},
		wantErr: ErrLifetime,
	}, {
		desc: "expired",
		sign: &SignOptions{
			Resource: "foo",
			Now:      now,
			Lifetime: time.Second,
		},
		verify: &VerifyOptions{
			Resource:      "foo",
			Now:           now.Add(time.Second + time.Nanosecond),
			NonceVerifier: &fakeNonceVerifier{},
		},
		wantErr: ErrLifetime,
	}, {
		desc: "nonce reused",
		sign: &SignOptions{
			Resource: "foo",
			Now:      now,
			Lifetime: time.Second,
		},
		verify: &VerifyOptions{
			Resource:      "foo",
			Now:           now.Add(time.Second),
			NonceVerifier: &fakeNonceVerifier{nonce.ErrReused},
		},
		wantErr: nonce.ErrReused,
	}, {
		desc: "not before skew",
		sign: &SignOptions{
			Resource: "foo",
			Now:      now.Add(time.Millisecond),
			Lifetime: time.Second,
		},
		verify: &VerifyOptions{
			Resource: "foo",
			Now:      now,
			Skew:     time.Millisecond,
		},
	}, {
		desc: "not after skew",
		sign: &SignOptions{
			Resource: "foo",
			Now:      now,
			Lifetime: time.Second,
		},
		verify: &VerifyOptions{
			Resource: "foo",
			Now:      now.Add(time.Second + time.Millisecond),
			Skew:     time.Millisecond,
		},
	}}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			token, sid, err := signer.Sign(tc.sign)
			if err != nil {
				t.Fatal(err)
			}
			subject, vid, err := verifier.Verify(token, tc.verify)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("Verify(%v) failed: %v", tc.verify, err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Verify(%v) = %v, wanted %v", tc.verify, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if subject != "test" {
				t.Errorf("expected subject \"test\", got %q", subject)
			}
			if sid != vid {
				t.Errorf("token ID from sign (%s) does not match token ID from verify (%s)", sid, vid)
			}
		})
	}
}
