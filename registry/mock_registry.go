package officialRegistryMock

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// OfficialVoterRegistry interface defines the methods required for voter verification
type OfficialVoterRegistry interface {
	VoterExists(personalCode string) bool
	GetVoterDetails(personalCode string) (*VoterDetails, error)
	IsVoterRegistered(personalCode string) bool
	LoadTestData() error
}

// VoterDetails contains the official voter information
type VoterDetails struct {
	PersonalCode string    `json:"personal_code"`
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	DateOfBirth  time.Time `json:"date_of_birth"`
	Citizenship  string    `json:"citizenship"`
	Address      string    `json:"address"`
	IsActive     bool      `json:"is_active"` // Indicates if the voter is eligible (not deceased, etc.)
	LastUpdated  time.Time `json:"last_updated"`
	UniqueCode   string    `json:"unique_code"` // Add this field
}

// MockVoterRegistry implements OfficialVoterRegistry interface
type MockVoterRegistry struct {
	voters     map[string]*VoterDetails
	registered map[string]bool
	mu         sync.RWMutex
	config     RegistryConfig
}

type RegistryConfig struct {
	VotersFilePath string `json:"voters_file_path"`
	AutoSave       bool   `json:"auto_save"`
}

func (m *MockVoterRegistry) LoadTestData() error {
	return m.LoadVotersFromFile()
}

// NewMockVoterRegistry creates a new instance of MockVoterRegistry
func NewMockVoterRegistry(config RegistryConfig) (*MockVoterRegistry, error) {
	registry := &MockVoterRegistry{
		voters:     make(map[string]*VoterDetails),
		registered: make(map[string]bool),
		config:     config,
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(config.VotersFilePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %v", err)
	}

	return registry, nil
}

// LoadTestData loads mock voter data from JSON file or creates default test data
func (m *MockVoterRegistry) LoadVotersFromFile() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.config.VotersFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return m.createDefaultVotersFile()
		}
		return fmt.Errorf("failed to read voters file: %v", err)
	}

	var votersData struct {
		Voters []*VoterDetails `json:"voters"`
	}

	if err := json.Unmarshal(data, &votersData); err != nil {
		return fmt.Errorf("failed to unmarshal voter data: %v", err)
	}

	// Clear existing data and load new data
	m.voters = make(map[string]*VoterDetails)
	for _, voter := range votersData.Voters {
		// Validate voter data
		if err := validateVoterData(voter); err != nil {
			return fmt.Errorf("invalid voter data for %s: %v", voter.PersonalCode, err)
		}
		m.voters[voter.PersonalCode] = voter
	}

	return nil
}

func (m *MockVoterRegistry) createDefaultVotersFile() error {
	defaultVoters := struct {
		Voters []*VoterDetails `json:"voters"`
	}{
		Voters: []*VoterDetails{
			{
				PersonalCode: "39001011234",
				FirstName:    "Jonas",
				LastName:     "Jonaitis",
				DateOfBirth:  time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC),
				Citizenship:  "LT",
				Address:      "Gedimino pr. 1, Vilnius",
				IsActive:     true,
				LastUpdated:  time.Now(),
			},
			// ... other default voters ...
		},
	}

	data, err := json.MarshalIndent(defaultVoters, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal default voter data: %v", err)
	}

	if err := os.WriteFile(m.config.VotersFilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to save default voters file: %v", err)
	}

	// Load the default data into memory
	for _, voter := range defaultVoters.Voters {
		m.voters[voter.PersonalCode] = voter
	}

	return nil
}

func validateVoterData(voter *VoterDetails) error {
	if voter.PersonalCode == "" {
		return fmt.Errorf("personal code is required")
	}
	if voter.FirstName == "" {
		return fmt.Errorf("first name is required")
	}
	if voter.LastName == "" {
		return fmt.Errorf("last name is required")
	}
	if voter.DateOfBirth.IsZero() {
		return fmt.Errorf("date of birth is required")
	}
	if voter.Citizenship == "" {
		return fmt.Errorf("citizenship is required")
	}
	return nil
}

func (m *MockVoterRegistry) VoterExists(personalCode string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	voter, exists := m.voters[personalCode]
	return exists && voter.IsActive
}

func (m *MockVoterRegistry) GetVoterDetails(personalCode string) (*VoterDetails, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	voter, exists := m.voters[personalCode]
	if !exists {
		return nil, fmt.Errorf("voter with personal code %s not found", personalCode)
	}

	if !voter.IsActive {
		return nil, fmt.Errorf("voter with personal code %s is inactive", personalCode)
	}

	// Return a copy to prevent modification of internal state
	voterCopy := *voter
	return &voterCopy, nil
}

func (m *MockVoterRegistry) IsVoterRegistered(personalCode string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.registered[personalCode]
}

func (m *MockVoterRegistry) RegisterVoter(personalCode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.registered[personalCode] {
		return fmt.Errorf("voter with personal code %s is already registered", personalCode)
	}

	voter, exists := m.voters[personalCode]
	if !exists {
		return fmt.Errorf("voter with personal code %s not found", personalCode)
	}

	if !voter.IsActive {
		return fmt.Errorf("voter with personal code %s is inactive", personalCode)
	}

	m.registered[personalCode] = true
	return nil
}

// TestHelper functions for easier testing
type TestHelper struct {
	registry *MockVoterRegistry
}

func NewTestHelper(registry *MockVoterRegistry) *TestHelper {
	return &TestHelper{registry: registry}
}

func (th *TestHelper) AddTestVoter(voter *VoterDetails) error {
	th.registry.mu.Lock()
	defer th.registry.mu.Unlock()

	th.registry.voters[voter.PersonalCode] = voter
	return nil
}

func (th *TestHelper) RemoveTestVoter(personalCode string) {
	th.registry.mu.Lock()
	defer th.registry.mu.Unlock()

	delete(th.registry.voters, personalCode)
	delete(th.registry.registered, personalCode)
}
