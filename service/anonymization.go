package service

import (
	"crypto/rand"
	"math/big"
	"sort"
	"time"
	"voting-backend/models"
)

type AnonymizationService struct {
	batchSize int
	mixWindow time.Duration
}

func NewAnonymizationService(batchSize int, mixWindow time.Duration) *AnonymizationService {
	return &AnonymizationService{
		batchSize: batchSize,
		mixWindow: mixWindow,
	}
}

func (as *AnonymizationService) AnonymizeVotes(votes []models.Vote) []models.Vote {
	if len(votes) <= 1 {
		return votes
	}

	// Create a copy of votes to avoid modifying the original slice
	anonymizedVotes := make([]models.Vote, len(votes))
	copy(anonymizedVotes, votes)

	// Process votes in batches
	for i := 0; i < len(anonymizedVotes); i += as.batchSize {
		end := i + as.batchSize
		if end > len(anonymizedVotes) {
			end = len(anonymizedVotes) // Handle last smaller batch
		}

		batch := anonymizedVotes[i:end]

		// Shuffle batch
		for j := len(batch) - 1; j > 0; j-- {
			rndIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(j+1)))
			batch[j], batch[rndIndex.Int64()] = batch[rndIndex.Int64()], batch[j]
		}

		// Find min/max timestamps in the batch
		minTime, maxTime := batch[0].Timestamp, batch[0].Timestamp
		for _, vote := range batch {
			if vote.Timestamp < minTime {
				minTime = vote.Timestamp
			}
			if vote.Timestamp > maxTime {
				maxTime = vote.Timestamp
			}
		}

		// Redistribute timestamps randomly within the mixWindow
		for j := range batch {
			offset, _ := rand.Int(rand.Reader, big.NewInt(as.mixWindow.Milliseconds()))
			batch[j].Timestamp = minTime + offset.Int64()
		}

		// Sort by new timestamps to maintain chronological order
		sort.Slice(batch, func(a, b int) bool {
			return batch[a].Timestamp < batch[b].Timestamp
		})

		// Copy back processed batch
		copy(anonymizedVotes[i:end], batch)
	}

	return anonymizedVotes
}

func (as *AnonymizationService) RemoveVoterSignatures(vote models.Vote) models.Vote {
	vote.Signature = nil
	return vote
}
