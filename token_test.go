package token

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	pb "jdtw.dev/token/proto/token"
)

func generateKeys(t *testing.T, subjects ...string) (*VerificationKeyset, []*SigningKey) {
	t.Helper()
	ks := NewVerificationKeyset()
	signers := make([]*SigningKey, len(subjects))
	for i, sub := range subjects {
		var verifier *VerificationKey
		var err error
		verifier, signers[i], err = GenerateKey(sub)
		if err != nil {
			t.Fatal(err)
		}
		if err := ks.Add(verifier); err != nil {
			t.Fatal(err)
		}
	}
	return ks, signers
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

func TestVerifyWrongKey(t *testing.T) {
	verifier, signers := generateKeys(t, "alice", "bob")

	// Sign with Alice's key...
	signed, err := signers[0].Sign(WithResource("foo"))
	if err != nil {
		t.Fatal(err)
	}

	// Replace the Key ID with Bob's key...
	signedProto, _ := unmarshalToken(t, signed)
	signedProto.KeyId = signers[1].key.Id
	signed = marshal(t, signedProto)

	// Verification should fail.
	if _, err := verifier.Verify(signed); err == nil { // if NO error
		t.Errorf("expected verification failure")
	}

	// Now replace with an unknown Key ID...
	signedProto.KeyId = "unknown"
	signed = marshal(t, signedProto)

	// And verification should fail again...
	if _, err := verifier.Verify(signed); err == nil { // if NO error
		t.Errorf("expected verification failure")
	}
}

func TestSignVerify(t *testing.T) {
	verifier, signers := generateKeys(t, "test")
	signer := signers[0]
	tests := []struct {
		desc    string
		options []TokenOption
		checks  []TokenCheck
		wantErr bool
	}{{
		desc:    "success without resource check",
		options: []TokenOption{WithResource("foo")},
	}, {
		desc:    "success",
		options: []TokenOption{WithResource("foo")},
		checks:  []TokenCheck{CheckResource("foo")},
	}, {
		desc:    "wrong resource fails",
		options: []TokenOption{WithResource("foo")},
		checks:  []TokenCheck{CheckResource("bar")},
		wantErr: true,
	}, {
		desc:    "not valid yet",
		options: []TokenOption{WithResource("foo"), WithExpiry(time.Unix(1, 0), time.Second)},
		checks:  []TokenCheck{CheckExpiry(time.Unix(0, 0))},
		wantErr: true,
	}, {
		desc:    "expired",
		options: []TokenOption{WithResource("foo"), WithExpiry(time.Unix(1, 0), time.Second)},
		checks:  []TokenCheck{CheckExpiry(time.Unix(2, 1))},
		wantErr: true,
	}}
	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			token, err := signer.Sign(tc.options...)
			if err != nil {
				t.Fatal(err)
			}
			subject, err := verifier.Verify(token, tc.checks...)
			switch {
			case !tc.wantErr && err != nil:
				t.Fatalf("Verify failed: %v", err)
			case tc.wantErr && err == nil:
				t.Fatalf("Verify succeeded, wanted failure")
			}
			if err == nil && subject != "test" {
				t.Fatalf("expected subject \"test\", got %q", subject)
			}
		})
	}
}
