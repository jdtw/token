package token

import (
	"encoding/hex"
	"errors"
	"log"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"jdtw.dev/token/nonce"
	pb "jdtw.dev/token/proto/token"
)

func generateKeys(t *testing.T, subjects ...string) (*VerificationKeyset, map[string]*SigningKey) {
	t.Helper()
	ks := NewVerificationKeyset()
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
	if v.ID() != s.key.Id {
		t.Errorf("Public key ID %q doesn't match private key ID %q", v.ID(), s.key.Id)
	}
	if v.ID() == "" {
		t.Errorf("Empty key ID")
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

	// Replace the Key ID with Bob's key...
	signedProto, _ := unmarshalToken(t, signed)
	signedProto.KeyId = signers["bob"].key.Id
	signed = marshal(t, signedProto)

	// Verification should fail.
	if _, _, err := verifier.Verify(signed, vopts); !errors.Is(err, ErrSignature) {
		t.Errorf("Verify(%v) = %v, want %v", vopts, err, ErrSignature)
	}

	// Now replace with an unknown Key ID...
	signedProto.KeyId = "unknown"
	signed = marshal(t, signedProto)

	// And verification should fail again...
	if _, _, err := verifier.Verify(signed, vopts); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("Verify(%v) = %v, want %v", vopts, err, ErrUnknownKey)
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

func FuzzVerify(f *testing.F) {
	st := &pb.SignedToken{
		KeyId:     "foo",
		Signature: []byte("YELLOW SUBMARINE"),
	}
	bs, err := proto.Marshal(st)
	if err != nil {
		f.Fatal(err)
	}
	log.Println(hex.EncodeToString(bs))
	f.Add(bs)
	t := &pb.Token{
		Resource: "bar",
		Nonce:    []byte("1234"),
	}
	bs, err = proto.Marshal(t)
	if err != nil {
		f.Fatal(err)
	}
	st.Token = bs
	bs, err = proto.Marshal(st)
	if err != nil {
		f.Fatal(err)
	}
	pub, priv, err := GenerateKey("alice")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(bs)
	log.Println(hex.EncodeToString(bs))
	ids := make(map[string]struct{})
	for i := 0; i < 10; i++ {
		bs, id, err := priv.Sign(&SignOptions{
			Resource: "resource",
			Now:      time.Now(),
			Lifetime: time.Minute * time.Duration(i+1),
		})
		ids[id] = struct{}{}
		if err != nil {
			f.Fatal(err)
		}
		f.Add(bs)
	}
	ks := NewVerificationKeyset()
	if err := ks.Add(pub); err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, a []byte) {
		subject, id, err := ks.Verify(a, &VerifyOptions{
			Resource:      "resource",
			Now:           time.Now(),
			NonceVerifier: noOp{},
		})
		if err != nil {
			return
		}
		if _, ok := ids[id]; !ok {
			t.Errorf("Verified a token with unknown ID %s", id)
		}
		if subject != "alice" {
			t.Errorf("Verified unknown subject %s", subject)
		}
	})
}

type noOp struct{}

func (n noOp) Verify(nonce []byte, expires time.Time) error {
	return nil
}
