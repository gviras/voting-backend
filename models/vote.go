package models

type Vote struct {
	ID              string `json:"id"`
	EncryptedChoice []byte `json:"encrypted_choice"` // Contains VoteEncryptionPackage
	Nonce           []byte `json:"nonce"`
	Timestamp       int64  `json:"timestamp"`
	Signature       []byte `json:"signature,omitempty"`
	PrivateKeyHash  []byte `json:"private_key_hash,omitempty"`
}

type VotePayload struct {
	Choice     string
	VoterID    string
	ElectionID string
	Nonce      []byte
}
