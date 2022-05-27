package token

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	pb "jdtw.dev/token/proto/token"
)

type VerificationKey struct {
	key *pb.VerificationKey
}

type VerificationKeyset struct {
	keys *pb.VerificationKeyset
}

func NewVerificationKeyset() *VerificationKeyset {
	return &VerificationKeyset{&pb.VerificationKeyset{
		Keys: make(map[string]*pb.VerificationKey),
	}}
}

func UnmarshalVerificationKeyset(serialized []byte) (*VerificationKeyset, error) {
	keyset := &pb.VerificationKeyset{}
	if err := proto.Unmarshal(serialized, keyset); err != nil {
		return nil, err
	}
	if keyset.Keys == nil {
		keyset.Keys = make(map[string]*pb.VerificationKey)
	}
	return &VerificationKeyset{keyset}, nil
}

func (v *VerificationKeyset) Add(key *VerificationKey) error {
	keypb := key.key
	if keypb.Id == "" {
		return errors.New("missing ID")
	}
	if keypb.Subject == "" {
		return errors.New("missing subject")
	}
	if got, want := len(keypb.PublicKey), ed25519.PublicKeySize; got != want {
		return fmt.Errorf("invalid key size; got %d, want %d", got, want)
	}
	v.keys.Keys[keypb.Id] = key.key
	return nil
}

func (v *VerificationKeyset) Marshal() ([]byte, error) {
	return proto.Marshal(v.keys)
}

func (v *VerificationKeyset) String() string {
	return prototext.Format(v.keys)
}

type TokenCheck func(*pb.Token) error

func CheckExpiry(now time.Time) TokenCheck {
	return func(t *pb.Token) error {
		if t.NotBefore == nil || t.NotAfter == nil {
			return errors.New("token missing expiry")
		}
		if now.Before(t.NotBefore.AsTime()) {
			return errors.New("token not valid yet")
		}
		if now.After(t.NotAfter.AsTime()) {
			return errors.New("token expired")
		}
		return nil
	}
}

func CheckResource(resource string) TokenCheck {
	return func(t *pb.Token) error {
		if t.Resource != resource {
			return fmt.Errorf("got resource %q, want %q", t.Resource, resource)
		}
		return nil
	}
}

// Verify the given token and return the subject that signed it.
func (v *VerificationKeyset) Verify(token []byte, checks ...TokenCheck) (string, error) {
	// Unmarshal the signed token.
	signed := &pb.SignedToken{}
	if err := proto.Unmarshal(token, signed); err != nil {
		return "", err
	}

	// Fetch the verification key.
	k := v.keys.Keys[signed.KeyId]
	if k == nil {
		return "", fmt.Errorf("key %q not found", signed.KeyId)
	}

	// Verify the signature.
	pub := ed25519.PublicKey(k.PublicKey)
	toVerify := append([]byte(header), signed.Token...)
	if !ed25519.Verify(pub, toVerify, signed.Signature) {
		return "", fmt.Errorf("invalid signature")
	}

	// The token is cryptographically valid. Check contents.
	t := &pb.Token{}
	if err := proto.Unmarshal(signed.Token, t); err != nil {
		return "", err
	}
	for _, check := range checks {
		if err := check(t); err != nil {
			return "", err
		}
	}
	return k.Subject, nil
}
