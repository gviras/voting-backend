// File: models/types.go
package models

// Remove unused imports since we don't directly use them in this file
type DistributedKeyBlock struct {
	Timestamp int64
	PrevHash  string
	Hash      string
	VoterKeys []VoterKeyPair
	Nonce     int
}

type VoterKeyPair struct {
	VoterID   string
	PublicKey []byte
	IssuedAt  int64
	HasVoted  bool
}

type EncryptedVoteBlock struct {
	Timestamp      int64
	PrevHash       string
	Hash           string
	EncryptedVotes []EncryptedVote
	Nonce          int
}

type EncryptedVote struct {
	EncryptedBallot []byte
	Nonce           []byte
	PrivateKeyHash  string
	VoteHash        string // Add this field
	Timestamp       int64
}

type Ballot struct {
	VoteChoice     string `json:"vote_choice"`
	BlindingFactor []byte `json:"blinding_factor"`
	Timestamp      int64  `json:"timestamp"`
}
