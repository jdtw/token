package token

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"jdtw.dev/token/nonce"
	pb "jdtw.dev/token/proto/token"
)

var (
	ErrUnknownKey = errors.New("unknown key")
	ErrSignature  = errors.New("invalid signature")
	ErrLifetime   = errors.New("invalid lifetime")
	ErrResource   = errors.New("invalid resource")
)

type VerificationKey struct {
	key *pb.VerificationKey
}

// ID returns the key identifier for this key.
func (v *VerificationKey) ID() string {
	return v.key.Id
}

// Subject returns the subject for this key.
func (v *VerificationKey) Subject() string {
	return v.key.Subject
}

// UnmarshalVerificationKey unmarshals a signing key from a binary proto.
func UnmarshalVerificationKey(serialized []byte) (*VerificationKey, error) {
	key := &pb.VerificationKey{}
	if err := proto.Unmarshal(serialized, key); err != nil {
		return nil, err
	}
	if key.Subject == "" {
		return nil, ErrMissingSubject
	}
	if key.Id == "" {
		return nil, ErrMissingID
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvaidKeyLen
	}
	return &VerificationKey{key}, nil
}

// Marshal the verification key to binary proto.
func (k *VerificationKey) Marshal() ([]byte, error) {
	return proto.Marshal(k.key)
}

// String returns the JSON-encoded key.
func (k *VerificationKey) String() string {
	return protojson.Format(k.key)
}

// VerificationKeyset contains a map of key IDs to verification keys.
type VerificationKeyset struct {
	keys *pb.VerificationKeyset
}

// NewKeyset creates an empty keyset.
func NewKeyset() *VerificationKeyset {
	return &VerificationKeyset{&pb.VerificationKeyset{
		Keys: make(map[string]*pb.VerificationKey),
	}}
}

// UnmarshalKeyset unmarshals a keyset from a binary proto.
func UnmarshalKeyset(serialized []byte) (*VerificationKeyset, error) {
	keyset := &pb.VerificationKeyset{}
	if err := proto.Unmarshal(serialized, keyset); err != nil {
		return nil, err
	}
	if keyset.Keys == nil {
		keyset.Keys = make(map[string]*pb.VerificationKey)
	}
	return &VerificationKeyset{keyset}, nil
}

// Add a verification key to the keyset.
func (v *VerificationKeyset) Add(key *VerificationKey) error {
	keypb := key.key
	if keypb.Id == "" {
		return ErrMissingID
	}
	if keypb.Subject == "" {
		return ErrMissingSubject
	}
	if len(keypb.PublicKey) != ed25519.PublicKeySize {
		return ErrInvaidKeyLen
	}
	v.keys.Keys[keypb.Id] = key.key
	return nil
}

// Remove a verification key from the keyset by ID.
func (v *VerificationKeyset) Remove(id string) {
	delete(v.keys.Keys, id)
}

// Marshal the keyset into a binary proto.
func (v *VerificationKeyset) Marshal() ([]byte, error) {
	return proto.Marshal(v.keys)
}

// String returns the JSON-encoded keyset.
func (v *VerificationKeyset) String() string {
	return protojson.Format(v.keys)
}

// VerifyOptions contain the options for verifying a signed token.
type VerifyOptions struct {
	// The expected resource.
	Resource string
	// The current time. If zero, the current time will be used.
	Now time.Time
	// The interface with which to verify the token's nonce. If nil,
	// the nonce will not be checked for reuse.
	NonceVerifier nonce.Verifier
	// How much clock skew to allow for.
	Skew time.Duration
}

// Verify the given token. Returns the subject that signed the token and the token's unique ID
// as a hex encoded string.
func (v *VerificationKeyset) Verify(token []byte, opts *VerifyOptions) (string, string, error) {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	// Unmarshal the signed token.
	signed := &pb.SignedToken{}
	if err := proto.Unmarshal(token, signed); err != nil {
		return "", "", err
	}

	// Fetch the verification key.
	k, ok := v.keys.Keys[signed.KeyId]
	if !ok {
		return "", "", fmt.Errorf("%w: %s", ErrUnknownKey, signed.KeyId)
	}

	// Verify the signature.
	pub := ed25519.PublicKey(k.PublicKey)
	toVerify := append([]byte(header), signed.Token...)
	if !ed25519.Verify(pub, toVerify, signed.Signature) {
		return "", "", ErrSignature
	}

	// The token is cryptographically valid. Check contents.
	t := &pb.Token{}
	if err := proto.Unmarshal(signed.Token, t); err != nil {
		return "", "", err
	}

	// Check expiry...
	if t.NotBefore == nil || t.NotAfter == nil {
		return "", "", fmt.Errorf("%w: token missing lifetime", ErrLifetime)
	}
	notBefore, notAfter := t.NotBefore.AsTime(), t.NotAfter.AsTime()
	if now.Add(opts.Skew).Before(notBefore) {
		return "", "", fmt.Errorf("%w: token not valid until %s (now %s, skew %s)", ErrLifetime, notBefore, now, opts.Skew)
	}
	if now.Add(-opts.Skew).After(notAfter) {
		return "", "", fmt.Errorf("%w: token expired at %s (now %s, skew %s)", ErrLifetime, notAfter, now, opts.Skew)
	}

	// Check the desired resource...
	if t.Resource != opts.Resource {
		return "", "", fmt.Errorf("%w: got %q, want %q", ErrResource, t.Resource, opts.Resource)
	}

	// Check the nonce...
	hn := hex.EncodeToString(t.Nonce)
	if opts.NonceVerifier != nil {
		if err := opts.NonceVerifier.Verify(t.Nonce, notAfter); err != nil {
			return "", "", fmt.Errorf("verify nonce %s failed: %w", hn, err)
		}
	}
	return k.Subject, hn, nil
}
