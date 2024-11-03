package service

import (
	"sync"
	"time"
)

type VotingSession struct {
	startTime time.Time
	endTime   time.Time
	isActive  bool
	mu        sync.RWMutex
}

func NewVotingSession(duration time.Duration) *VotingSession {
	now := time.Now()
	return &VotingSession{
		startTime: now,
		endTime:   now.Add(duration),
		isActive:  true,
	}
}

func (vs *VotingSession) IsActive() bool {
	vs.mu.RLock()
	defer vs.mu.RUnlock()
	return vs.isActive && time.Now().Before(vs.endTime)
}

func (vs *VotingSession) End() {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.isActive = false
}
