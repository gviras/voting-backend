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
	Nonce      []byte
}
