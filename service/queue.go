// service/queue.go
package service

import (
	"crypto/ecdsa"
	"log"
	"sync"
	"time"
	"voting-backend/models"
)

// QueueProcessor handles the asynchronous processing of voter registrations and votes
type QueueProcessor struct {
	votingService   *VotingService
	registrationCh  chan *RegistrationRequest
	voteCh          chan *VoteRequest
	resultCh        chan *ProcessingResult
	processingWg    sync.WaitGroup
	shutdownCh      chan struct{}
	processingDelay time.Duration // For benchmarking purposes
}

// RegistrationRequest represents a queued voter registration request
type RegistrationRequest struct {
	Identity *models.VoterIdentity
	ResultCh chan<- *ProcessingResult
}

// VoteRequest represents a queued vote casting request
type VoteRequest struct {
	VoterID    string
	Vote       *models.VotePayload
	PrivateKey *ecdsa.PrivateKey
	ResultCh   chan<- *ProcessingResult
}

// ProcessingResult contains the result of an asynchronous operation
type ProcessingResult struct {
	Success      bool
	VoterID      string
	PrivateKey   *ecdsa.PrivateKey
	ErrorMessage string
	VoteID       string
	Timestamp    int64
}

// NewQueueProcessor creates a new queue processor
func NewQueueProcessor(votingService *VotingService, queueSize int, processingDelay time.Duration) *QueueProcessor {
	return &QueueProcessor{
		votingService:   votingService,
		registrationCh:  make(chan *RegistrationRequest, queueSize),
		voteCh:          make(chan *VoteRequest, queueSize),
		resultCh:        make(chan *ProcessingResult, queueSize*2),
		shutdownCh:      make(chan struct{}),
		processingDelay: processingDelay,
	}
}

// Start begins processing queued registrations and votes
func (qp *QueueProcessor) Start() {
	// Start workers for registrations
	qp.processingWg.Add(1)
	go qp.registrationWorker()

	qp.processingWg.Add(1)
	go qp.voteWorker()
}

func (qp *QueueProcessor) QueueVoteNoWait(voterID string, vote *models.VotePayload, privateKey *ecdsa.PrivateKey) {
	// Create a result channel but don't return it
	resultCh := make(chan *ProcessingResult, 1)

	select {
	case qp.voteCh <- &VoteRequest{
		VoterID:    voterID,
		Vote:       vote,
		PrivateKey: privateKey,
		ResultCh:   resultCh,
	}:
		// Successfully added to queue
		return
	default:
		// Queue is full, log but don't block
		log.Printf("Warning: vote queue is full, request for voter %s dropped", voterID)
		return
	}
}

// Stop gracefully shuts down the queue processor
func (qp *QueueProcessor) Stop() {
	close(qp.shutdownCh)
	qp.processingWg.Wait()
	close(qp.resultCh)
}

// QueueRegistration adds a voter registration request to the processing queue
func (qp *QueueProcessor) QueueRegistration(identity *models.VoterIdentity) <-chan *ProcessingResult {
	resultCh := make(chan *ProcessingResult, 1)
	select {
	case qp.registrationCh <- &RegistrationRequest{
		Identity: identity,
		ResultCh: resultCh,
	}:
		return resultCh
	default:
		// Queue is full, return immediate error
		resultCh <- &ProcessingResult{
			Success:      false,
			ErrorMessage: "registration queue is full",
		}
		close(resultCh)
		return resultCh
	}
}

// QueueVote adds a vote casting request to the processing queue
func (qp *QueueProcessor) QueueVote(voterID string, vote *models.VotePayload, privateKey *ecdsa.PrivateKey) <-chan *ProcessingResult {
	resultCh := make(chan *ProcessingResult, 1)
	select {
	case qp.voteCh <- &VoteRequest{
		VoterID:    voterID,
		Vote:       vote,
		PrivateKey: privateKey,
		ResultCh:   resultCh,
	}:
		return resultCh
	default:
		// Queue is full, return immediate error
		resultCh <- &ProcessingResult{
			Success:      false,
			ErrorMessage: "vote queue is full",
		}
		close(resultCh)
		return resultCh
	}
}

// registrationWorker processes queued voter registrations
func (qp *QueueProcessor) registrationWorker() {
	defer qp.processingWg.Done()

	for {
		select {
		case <-qp.shutdownCh:
			return
		case req := <-qp.registrationCh:
			// Add artificial delay for benchmarking if needed
			if qp.processingDelay > 0 {
				time.Sleep(qp.processingDelay)
			}

			// Start recording metrics
			qp.votingService.metricsCollector.RecordRegistrationStart()
			startTime := time.Now()

			// Process registration
			registeredVoter, err := qp.votingService.RegisterVoter(req.Identity)

			// Complete recording metrics
			processingTime := time.Since(startTime)
			qp.votingService.metricsCollector.RecordRegistrationEnd(processingTime)

			if err != nil {
				req.ResultCh <- &ProcessingResult{
					Success:      false,
					ErrorMessage: err.Error(),
				}
			} else {
				req.ResultCh <- &ProcessingResult{
					Success:    true,
					VoterID:    registeredVoter.VoterID,
					PrivateKey: registeredVoter.PrivateKey,
				}
			}
			close(req.ResultCh)
		}
	}
}

// voteWorker processes queued votes
func (qp *QueueProcessor) voteWorker() {
	defer qp.processingWg.Done()

	for {
		select {
		case <-qp.shutdownCh:
			return
		case req := <-qp.voteCh:
			// Add artificial delay for benchmarking if needed
			if qp.processingDelay > 0 {
				time.Sleep(qp.processingDelay)
			}

			// Start recording metrics
			qp.votingService.metricsCollector.RecordVotingStart()
			startTime := time.Now()

			// Process vote
			err := qp.votingService.CastVote(req.VoterID, req.Vote, req.PrivateKey)

			// Complete recording metrics
			processingTime := time.Since(startTime)
			qp.votingService.metricsCollector.RecordVotingEnd(processingTime)

			if err != nil {
				req.ResultCh <- &ProcessingResult{
					Success:      false,
					ErrorMessage: err.Error(),
				}
			} else {
				req.ResultCh <- &ProcessingResult{
					Success:   true,
					VoterID:   req.VoterID,
					Timestamp: time.Now().Unix(),
				}
			}
			close(req.ResultCh)
		}
	}
}

// GetResultChannel returns the channel where all processing results are sent
// This can be used for monitoring or benchmarking
func (qp *QueueProcessor) GetResultChannel() <-chan *ProcessingResult {
	return qp.resultCh
}

// BatchQueueRegistration adds multiple registration requests to the queue
// Useful for benchmarking
func (qp *QueueProcessor) BatchQueueRegistration(identities []*models.VoterIdentity) []<-chan *ProcessingResult {
	resultChannels := make([]<-chan *ProcessingResult, len(identities))
	for i, identity := range identities {
		resultChannels[i] = qp.QueueRegistration(identity)
	}
	return resultChannels
}

// BatchQueueVotes adds multiple vote requests to the queue
// Useful for benchmarking
func (qp *QueueProcessor) BatchQueueVotes(requests []VoteRequest) []<-chan *ProcessingResult {
	resultChannels := make([]<-chan *ProcessingResult, len(requests))
	for i, req := range requests {
		resultChannels[i] = qp.QueueVote(req.VoterID, req.Vote, req.PrivateKey)
	}
	return resultChannels
}
