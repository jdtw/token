package token

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"jdtw.dev/token/nonce"
	pb "jdtw.dev/token/proto/token"
)

const header = "jdtw.dev/token/v1"

type SigningKey struct {
	key *pb.SigningKey
}

func (s *SigningKey) ID() string {
	return s.key.Id
}

func (s *SigningKey) EncodeJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s.key)
}

// Generate an Ed25519 keypair for the given subject.
func GenerateKey(subject string) (*VerificationKey, *SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256([]byte(pub))
	keyID := hex.EncodeToString(digest[:])
	return &VerificationKey{&pb.VerificationKey{
			Id:        keyID,
			Subject:   subject,
			PublicKey: []byte(pub),
		}},
		&SigningKey{&pb.SigningKey{
			Id:         keyID,
			PrivateKey: []byte(priv)},
		},
		nil
}

// UnmarshalSigningKey unmarshals a signing key from a binary proto.
func UnmarshalSigningKey(serialized []byte) (*SigningKey, error) {
	key := &pb.SigningKey{}
	if err := proto.Unmarshal(serialized, key); err != nil {
		return nil, err
	}
	return &SigningKey{key}, nil
}

func (k *SigningKey) Marshal() ([]byte, error) {
	return proto.Marshal(k.key)
}

type SignOptions struct {
	// The resource this token will be used for.
	Resource string
	// The current time. If zero, the current time will be used.
	Now time.Time
	// How long the token should be valid for.
	Lifetime time.Duration
}

// Sign a token. Returns the signed token and its unique identifier as a hex encoded string.
func (k *SigningKey) Sign(opts *SignOptions) ([]byte, string, error) {
	if opts.Resource == "" {
		return nil, "", fmt.Errorf("token missing required resource")
	}
	if opts.Lifetime <= time.Duration(0) {
		return nil, "", fmt.Errorf("token lifetime must be greater than zero")
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	nonce, err := nonce.New()
	if err != nil {
		return nil, "", err
	}
	bytes, err := proto.Marshal(&pb.Token{
		Resource:  opts.Resource,
		NotBefore: timestamppb.New(now),
		NotAfter:  timestamppb.New(now.Add(opts.Lifetime)),
		Nonce:     nonce,
	})
	if err != nil {
		return nil, "", err
	}

	priv := ed25519.PrivateKey(k.key.PrivateKey)
	// Append the header before signing to prevent any sort of cross-protocol tomfoolery.
	toSign := append([]byte(header), bytes...)
	sig, err := priv.Sign(rand.Reader, toSign, crypto.Hash(0))
	if err != nil {
		return nil, "", err
	}
	bytes, err = proto.Marshal(&pb.SignedToken{
		KeyId:     k.key.Id,
		Signature: sig,
		Token:     bytes,
	})
	if err != nil {
		return nil, "", err
	}
	return bytes, hex.EncodeToString(nonce), nil
}
