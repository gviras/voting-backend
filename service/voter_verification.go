package service

import (
	"errors"
	"fmt"
	"regexp"
	"time"
	"voting-backend/models"
	"voting-backend/registry"
)

type VoterVerificationService struct {
	officialRegistry officialRegistryMock.OfficialVoterRegistry
	minimumAge       int
	allowedRegions   []string
	verifierID       string
}

func NewVoterVerificationService(registry officialRegistryMock.OfficialVoterRegistry) *VoterVerificationService {
	return &VoterVerificationService{
		officialRegistry: registry,
		minimumAge:       18,
		allowedRegions:   []string{"LT"},
		verifierID:       "DKB-VERIFIER-001", // Unique identifier for this verifier
	}
}

// VerifyVoter performs all necessary checks before registration
func (vvs *VoterVerificationService) VerifyVoter(identity *models.VoterIdentity) error {
	// 1. Verify personal code format and validity
	if err := vvs.verifyPersonalCode(identity.PersonalCode); err != nil {
		return fmt.Errorf("personal code validation failed: %w", err)
	}

	// 2. Check if voter exists in official registry
	if !vvs.officialRegistry.VoterExists(identity.PersonalCode) {
		return errors.New("voter not found in official registry")
	}

	// 3. Get and verify voter details from registry
	registryVoter, err := vvs.officialRegistry.GetVoterDetails(identity.PersonalCode)
	if err != nil {
		return fmt.Errorf("failed to verify voter in registry: %w", err)
	}

	// 4. Verify data consistency between provided identity and registry data
	if err := vvs.verifyIdentityMatch(identity, registryVoter); err != nil {
		return fmt.Errorf("identity verification failed: %w", err)
	}

	// 5. Verify age requirement
	age := vvs.calculateAge(identity.DateOfBirth)
	if age < vvs.minimumAge {
		return fmt.Errorf("voter must be at least %d years old (current age: %d)", vvs.minimumAge, age)
	}

	// 6. Verify citizenship
	if !vvs.isValidCitizenship(identity.Citizenship) {
		return fmt.Errorf("only Lithuanian citizens (LT) are eligible to vote, got: %s", identity.Citizenship)
	}

	// 7. Check if voter has already registered in the official registry
	if vvs.officialRegistry.IsVoterRegistered(identity.PersonalCode) {
		return fmt.Errorf("voter %s has already registered to vote", identity.PersonalCode)
	}

	return nil
}

func (vvs *VoterVerificationService) verifyPersonalCode(code string) error {
	// Basic format check
	if matched, _ := regexp.MatchString(`^\d{11}$`, code); !matched {
		return errors.New("personal code must be exactly 11 digits")
	}

	// Parse first digit for gender and century
	firstDigit := code[0]
	if firstDigit != '3' && firstDigit != '4' && // 1900-1999 (male/female)
		firstDigit != '5' && firstDigit != '6' { // 2000-2099 (male/female)
		return errors.New("invalid personal code: first digit must be 3, 4, 5, or 6")
	}

	// Validate birth date part
	year := code[1:3]
	month := code[3:5]
	day := code[5:7]

	centuryPrefix := "19"
	if firstDigit == '5' || firstDigit == '6' {
		centuryPrefix = "20"
	}

	birthDate, err := time.Parse("20060102", centuryPrefix+year+month+day)
	if err != nil {
		return fmt.Errorf("invalid birth date in personal code: %v", err)
	}

	// Validate the birthdate is not in the future
	if birthDate.After(time.Now()) {
		return errors.New("invalid personal code: birth date is in the future")
	}

	// Validate checksum
	if err := vvs.validatePersonalCodeChecksum(code); err != nil {
		return fmt.Errorf("invalid personal code checksum: %v", err)
	}

	return nil
}

func (vvs *VoterVerificationService) validatePersonalCodeChecksum(code string) error {
	weights1 := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 1}
	weights2 := []int{3, 4, 5, 6, 7, 8, 9, 1, 2, 3}

	sum := 0
	for i := 0; i < 10; i++ {
		digit := int(code[i] - '0')
		sum += digit * weights1[i]
	}

	remainder := sum % 11
	if remainder == 10 {
		sum = 0
		for i := 0; i < 10; i++ {
			digit := int(code[i] - '0')
			sum += digit * weights2[i]
		}
		remainder = sum % 11
		if remainder == 10 {
			remainder = 0
		}
	}

	checksum := int(code[10] - '0')
	if remainder != checksum {
		return errors.New("checksum verification failed")
	}

	return nil
}

func (vvs *VoterVerificationService) verifyIdentityMatch(identity *models.VoterIdentity, registryVoter *officialRegistryMock.VoterDetails) error {
	if identity.FirstName != registryVoter.FirstName {
		return errors.New("first name mismatch with registry")
	}
	if identity.LastName != registryVoter.LastName {
		return errors.New("last name mismatch with registry")
	}
	if !identity.DateOfBirth.Equal(registryVoter.DateOfBirth) {
		return errors.New("birth date mismatch with registry")
	}
	if identity.Citizenship != registryVoter.Citizenship {
		return errors.New("citizenship mismatch with registry")
	}
	if !registryVoter.IsActive {
		return errors.New("voter is marked as inactive in registry")
	}
	return nil
}

func (vvs *VoterVerificationService) calculateAge(birthDate time.Time) int {
	now := time.Now()
	age := now.Year() - birthDate.Year()

	if now.Month() < birthDate.Month() ||
		(now.Month() == birthDate.Month() && now.Day() < birthDate.Day()) {
		age--
	}
	return age
}

func (vvs *VoterVerificationService) isValidCitizenship(citizenship string) bool {
	for _, region := range vvs.allowedRegions {
		if citizenship == region {
			return true
		}
	}
	return false
}

func (vvs *VoterVerificationService) GetVerifierID() string {
	return vvs.verifierID
}
