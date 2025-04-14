package service

import (
	"fmt"
	"sync"
	"time"
)

// MetricsCollector tracks performance metrics for different operations
type MetricsCollector struct {
	mu                    sync.RWMutex
	registrationStartTime time.Time
	registrationEndTime   time.Time
	registrationCount     int
	registrationTotalTime time.Duration

	votingStartTime time.Time
	votingEndTime   time.Time
	votingCount     int
	votingTotalTime time.Duration

	votingPhaseStarted   bool
	votingPhaseStartTime time.Time
	votingPhaseEndTime   time.Time
	votingPhaseDuration  time.Duration

	countingStartTime      time.Time
	countingEndTime        time.Time
	countingProcessingTime time.Duration
}

// OperationMetrics contains timing information for an operation
type OperationMetrics struct {
	StartTime      time.Time `json:"start_time"`
	EndTime        time.Time `json:"end_time"`
	Count          int       `json:"count"`
	ProcessingTime int64     `json:"processing_time_ms"`
}

// MetricsResponse provides the metrics for all operations
type MetricsResponse struct {
	Registration OperationMetrics `json:"registration"`
	Voting       OperationMetrics `json:"voting"`
	Counting     OperationMetrics `json:"counting"`
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{}
}

// Add new methods
func (mc *MetricsCollector) StartVotingPhase() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.votingPhaseStarted = true
	mc.votingPhaseStartTime = time.Now()
}

func (mc *MetricsCollector) EndVotingPhase() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.votingPhaseStarted {
		mc.votingPhaseEndTime = time.Now()
		mc.votingPhaseDuration = mc.votingPhaseEndTime.Sub(mc.votingPhaseStartTime)
	}
}

// RecordRegistrationStart marks the start of a registration operation
func (mc *MetricsCollector) RecordRegistrationStart() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.registrationCount == 0 {
		mc.registrationStartTime = time.Now()
	}
	mc.registrationCount++
}

// RecordRegistrationEnd marks the end of a registration operation
func (mc *MetricsCollector) RecordRegistrationEnd(duration time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.registrationEndTime = time.Now()
	mc.registrationTotalTime += duration
}

// RecordVotingStart marks the start of a voting operation
func (mc *MetricsCollector) RecordVotingStart() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.votingCount == 0 {
		mc.votingStartTime = time.Now()
	}
	mc.votingCount++
}

// RecordVotingEnd marks the end of a voting operation
func (mc *MetricsCollector) RecordVotingEnd(duration time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.votingEndTime = time.Now()
	fmt.Printf("Adding duration: %v ns, current total: %v ns\n",
		duration.Nanoseconds(), mc.votingTotalTime.Nanoseconds())
	mc.votingTotalTime += duration
	fmt.Printf("New total: %v ns (%v ms)\n",
		mc.votingTotalTime.Nanoseconds(), mc.votingTotalTime.Milliseconds())
}

// RecordCountingStart marks the start of a counting operation
func (mc *MetricsCollector) RecordCountingStart() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.countingStartTime = time.Now()
}

// RecordCountingEnd marks the end of a counting operation
func (mc *MetricsCollector) RecordCountingEnd() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.countingEndTime = time.Now()
	mc.countingProcessingTime = mc.countingEndTime.Sub(mc.countingStartTime)
}

// GetMetrics returns current metrics for all operations
func (mc *MetricsCollector) GetMetrics() MetricsResponse {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return MetricsResponse{
		Registration: OperationMetrics{
			StartTime:      mc.registrationStartTime,
			EndTime:        mc.registrationEndTime,
			Count:          mc.registrationCount,
			ProcessingTime: mc.registrationTotalTime.Milliseconds(),
		},
		Voting: OperationMetrics{
			StartTime:      mc.votingStartTime,
			EndTime:        mc.votingEndTime,
			Count:          mc.votingCount,
			ProcessingTime: mc.votingTotalTime.Milliseconds(),
		},
		Counting: OperationMetrics{
			StartTime:      mc.countingStartTime,
			EndTime:        mc.countingEndTime,
			ProcessingTime: mc.countingProcessingTime.Milliseconds(),
		},
	}
}

// GetPhaseMetrics returns metrics for a specific phase
type PhaseMetricsResponse struct {
	ProcessingTimeMs int64     `json:"processing_time_ms"`
	Count            int       `json:"count"`
	PhaseStartTime   time.Time `json:"phase_start_time,omitempty"`
	PhaseEndTime     time.Time `json:"phase_end_time,omitempty"`
	PhaseDuration    int64     `json:"phase_duration_ms,omitempty"`
}

func (mc *MetricsCollector) GetPhaseMetrics(phase string) PhaseMetricsResponse {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	switch phase {
	case "registration":
		return PhaseMetricsResponse{
			ProcessingTimeMs: mc.registrationTotalTime.Milliseconds(),
			Count:            mc.registrationCount,
		}
	case "voting":
		return PhaseMetricsResponse{
			ProcessingTimeMs: mc.votingTotalTime.Milliseconds(),
			Count:            mc.votingCount,
			PhaseStartTime:   mc.votingPhaseStartTime,
			PhaseEndTime:     mc.votingPhaseEndTime,
			PhaseDuration:    mc.votingPhaseDuration.Milliseconds(),
		}
	case "counting":
		return PhaseMetricsResponse{
			ProcessingTimeMs: mc.countingProcessingTime.Milliseconds(),
			Count:            1, // Counting is a single operation
		}
	default:
		return PhaseMetricsResponse{}
	}
}

// Reset clears all metrics
func (mc *MetricsCollector) Reset() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.registrationStartTime = time.Time{}
	mc.registrationEndTime = time.Time{}
	mc.registrationCount = 0
	mc.registrationTotalTime = 0

	mc.votingStartTime = time.Time{}
	mc.votingEndTime = time.Time{}
	mc.votingCount = 0
	mc.votingTotalTime = 0

	mc.countingStartTime = time.Time{}
	mc.countingEndTime = time.Time{}
	mc.countingProcessingTime = 0
}
