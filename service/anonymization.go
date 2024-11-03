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
	if len(votes) == 0 {
		return votes
	}

	// Create a copy of votes
	anonymizedVotes := make([]models.Vote, len(votes))
	copy(anonymizedVotes, votes)

	// Shuffle votes
	for i := len(anonymizedVotes) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		anonymizedVotes[i], anonymizedVotes[j.Int64()] = anonymizedVotes[j.Int64()], anonymizedVotes[i]
	}

	// Mix timestamps
	baseTime := time.Now().Add(-as.mixWindow)
	for i := range anonymizedVotes {
		offset, _ := rand.Int(rand.Reader, big.NewInt(int64(as.mixWindow.Seconds())))
		anonymizedVotes[i].Timestamp = baseTime.Add(time.Duration(offset.Int64()) * time.Second).Unix()
	}

	// Sort by new timestamps
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
