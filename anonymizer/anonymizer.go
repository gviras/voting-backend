// File: anonymizer/anonymizer.go
package anonymizer

import (
	"math/rand" // Changed from crypto/rand to math/rand for Intn
	"time"
	"voting-backend/models"
)

type Anonymizer struct {
	Buffer []models.EncryptedVote
}

func New() *Anonymizer {
	return &Anonymizer{}
}

func (a *Anonymizer) ShuffleVotes(votes []models.EncryptedVote) []models.EncryptedVote {
	shuffled := make([]models.EncryptedVote, len(votes))
	copy(shuffled, votes)

	// Fisher-Yates shuffle
	for i := len(shuffled) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

		// Modify timestamps to further obscure ordering
		shuffled[i].Timestamp = time.Now().Unix()
	}

	return shuffled
}
