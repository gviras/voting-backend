package models

import "time"

type VoterIdentity struct {
	PersonalCode string    `json:"personal_code"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	DateOfBirth  time.Time `json:"date_of_birth"`
	Citizenship  string    `json:"citizenship"`
	Address      string    `json:"address"`
}

type VoterDeclaration struct {
	VoterID     string    `json:"voter_id"`
	Declaration string    `json:"declaration"`
	Timestamp   time.Time `json:"timestamp"`
}

type VoterRegistration struct {
	VoterID   string `json:"voter_id"`
	PublicKey []byte `json:"public_key"`
	Timestamp int64  `json:"timestamp"`
}
