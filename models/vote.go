package models

type Vote struct {
	ID              string
	EncryptedChoice []byte
	Nonce           []byte
	Timestamp       int64
	Signature       []byte
	PublicKeyHash   []byte
}

type VotePayload struct {
	Choice     string
	VoterID    string
	ElectionID string
}

type VoterRegistration struct {
	VoterID   string `json:"voter_id"`
	PublicKey []byte `json:"public_key"`
	Timestamp int64  `json:"timestamp"`
}
