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
	if len(votes) == 0 || len(votes) == 1 {
		return votes
	}

	// Create a copy of votes
	anonymizedVotes := make([]models.Vote, len(votes))
	copy(anonymizedVotes, votes)

	// If we have more than one vote, shuffle them
	for i := len(anonymizedVotes) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		anonymizedVotes[i], anonymizedVotes[j.Int64()] = anonymizedVotes[j.Int64()], anonymizedVotes[i]
	}

	// Find the earliest and latest timestamps in the batch
	var minTime, maxTime int64
	minTime = anonymizedVotes[0].Timestamp
	maxTime = anonymizedVotes[0].Timestamp

	for _, vote := range anonymizedVotes {
		if vote.Timestamp < minTime {
			minTime = vote.Timestamp
		}
		if vote.Timestamp > maxTime {
			maxTime = vote.Timestamp
		}
	}

	// Calculate time range for the batch
	timeRange := maxTime - minTime

	// Redistribute timestamps evenly within the original time range
	for i := range anonymizedVotes {
		offset, _ := rand.Int(rand.Reader, big.NewInt(timeRange))
		anonymizedVotes[i].Timestamp = minTime + offset.Int64()
	}

	// Sort by new timestamps to maintain chronological order
	sort.Slice(anonymizedVotes, func(i, j int) bool {
		return anonymizedVotes[i].Timestamp < anonymizedVotes[j].Timestamp
	})

	return anonymizedVotes
}

func (as *AnonymizationService) RemoveVoterSignatures(vote models.Vote) models.Vote {
	vote.Signature = nil
	vote.PublicKeyHash = nil
	return vote
}
