package encryption

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/roasbeef/go-go-gadget-paillier"
	"golang.org/x/crypto/sha3"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"voting-backend/models"
)

type VoteEncryptionPackage struct {
	HomomorphicVoteData map[string][]byte `json:"homomorphic_votes"` // Map of encrypted choice identifiers to vote counts
	ElectionData        []byte            `json:"election_data"`     // Election verification data
	Nonce               []byte            `json:"nonce"`             // For vote verification
}

// SchemeType represents the type of homomorphic encryption scheme
type SchemeType string

const (
	SchemePaillier SchemeType = "paillier"
	SchemeElGamal  SchemeType = "elgamal"
	// Add more schemes as needed
)

// PaillierKeyPair represents the public and private key pair.
type PaillierKeyPair struct {
	PublicKey  *paillier.PublicKey
	PrivateKey *paillier.PrivateKey
}

// SerializablePaillierPublicKey for public key serialization.
type SerializablePaillierPublicKey struct {
	N string `json:"n"` // Hex-encoded big.Int
}

// SerializablePaillierPrivateKey for private key serialization.
type SerializablePaillierPrivateKey struct {
	PublicKey SerializablePaillierPublicKey `json:"public_key"`
	Lambda    string                        `json:"lambda"` // Hex-encoded big.Int
	Mu        string                        `json:"mu"`     // Hex-encoded big.Int
}

func (cs *CryptoService) hashChoice(choice string) string {
	hash := cs.Keccak256([]byte(choice))
	// Convert to hex string for consistent representation
	return fmt.Sprintf("%x", hash)
}

func (cs *CryptoService) AddHomomorphicValues(value1, value2 []byte) ([]byte, error) {
	// This directly uses the scheme's Add method without unmarshaling/marshaling packages
	return cs.scheme.Add(value1, value2)
}

// DecryptToInt decrypts a homomorphic value to an integer directly
func (cs *CryptoService) DecryptToInt(encryptedValue []byte) (int64, error) {
	// Decrypt directly to a big.Int and convert to int64
	decrypted, err := cs.scheme.Decrypt(encryptedValue)
	if err != nil {
		return 0, err
	}

	// For values that fit in int64
	if decrypted.IsInt64() {
		return decrypted.Int64(), nil
	}

	return 0, fmt.Errorf("decrypted value too large for int64")
}

type CryptoService struct {
	// Original fields
	paillierPrivateKey *paillier.PrivateKey
	PaillierPublicKey  *paillier.PublicKey
	choiceMapping      map[string]string // maps hash to candidate name
	choiceMappingMu    sync.RWMutex      // separate mutex for choice mapping
	storagePath        string

	// New fields for scheme flexibility
	scheme     HomomorphicEncryptionScheme
	schemeType SchemeType
	keySize    int
}

// NewCryptoService initializes a new CryptoService
func NewCryptoService(storagePath string) (*CryptoService, error) {
	return NewCryptoServiceWithScheme(storagePath, SchemePaillier, 2048)
}

// NewCryptoServiceWithScheme initializes a CryptoService with a specific encryption scheme
func NewCryptoServiceWithScheme(storagePath string, schemeType SchemeType, keySize int) (*CryptoService, error) {
	// Debug log the storage path being used
	fmt.Printf("Initializing CryptoService with storage path: %s\n", storagePath)
	fmt.Printf("Using encryption scheme: %s with key size %d bits\n", schemeType, keySize)

	// Ensure the directory for the storage path exists
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %v", err)
	}

	cs := &CryptoService{
		storagePath:   storagePath,
		schemeType:    schemeType,
		keySize:       keySize,
		choiceMapping: make(map[string]string),
	}

	// Initialize the appropriate scheme
	var err error
	switch schemeType {
	case SchemePaillier:
		err = cs.initializePaillier()
	case SchemeElGamal:
		err = cs.initializeElGamal()
	default:
		return nil, fmt.Errorf("unsupported encryption scheme: %s", schemeType)
	}

	if err != nil {
		return nil, err
	}

	return cs, nil
}

// initializePaillier initializes the Paillier scheme
func (cs *CryptoService) initializePaillier() error {
	keysFile := cs.getKeysFilePath()
	fmt.Printf("Looking for Paillier keys file at: %s\n", keysFile)

	// Check if the file exists
	if _, err := os.Stat(keysFile); errors.Is(err, os.ErrNotExist) {
		// If the file does not exist, generate and save new keys
		fmt.Println("Paillier keys file not found, generating new keys...")
		keys, err := cs.generateAndSavePaillierKeys()
		if err != nil {
			return fmt.Errorf("failed to generate and save Paillier keys: %v", err)
		}

		cs.paillierPrivateKey = keys.PrivateKey
		cs.PaillierPublicKey = keys.PublicKey

		// Create adapter
		adapter := NewPaillierAdapter(cs.keySize, cs.paillierPrivateKey, cs.PaillierPublicKey)
		cs.scheme = adapter

		fmt.Println("New Paillier keys successfully generated and saved.")
		return nil
	} else if err != nil {
		// Handle unexpected errors when checking the file
		return fmt.Errorf("failed to check Paillier keys file: %v", err)
	}

	// If the file exists, load the keys
	fmt.Println("Paillier keys file found, loading keys...")
	keys, err := cs.loadPaillierKeys()
	if err != nil {
		return fmt.Errorf("failed to load Paillier keys: %v", err)
	}

	cs.paillierPrivateKey = keys.PrivateKey
	cs.PaillierPublicKey = keys.PublicKey

	// Create adapter
	adapter := NewPaillierAdapter(cs.keySize, cs.paillierPrivateKey, cs.PaillierPublicKey)
	adapter.privateKey = cs.paillierPrivateKey
	adapter.publicKey = cs.PaillierPublicKey
	cs.scheme = adapter

	fmt.Println("Paillier keys successfully loaded.")
	return nil
}

// initializeElGamal initializes the ElGamal scheme
func (cs *CryptoService) initializeElGamal() error {
	// Convert the requested key size to an appropriate EC curve size
	var ecKeySize int
	switch {
	case cs.keySize <= 1024:
		ecKeySize = 256 // P-256 curve ~ 128-bit security
	case cs.keySize <= 2048:
		ecKeySize = 384 // P-384 curve ~ 192-bit security
	default:
		ecKeySize = 521 // P-521 curve ~ 256-bit security
	}

	adapter := NewElGamalAdapter(ecKeySize)
	if err := adapter.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize ElGamal: %v", err)
	}

	cs.scheme = adapter
	fmt.Printf("ElGamal with EC-%d initialized successfully\n", ecKeySize)
	return nil
}

// For backward compatibility
func (cs *CryptoService) EncryptVoteData(votePayload models.VotePayload) ([]byte, error) {
	// Hash and store choice mapping
	choiceHash := cs.storeChoiceMapping(votePayload.Choice)

	homomorphicVotes := make(map[string][]byte)

	// Use the current scheme for encryption
	voteValue := big.NewInt(1) // We're encoding a single vote as 1
	encryptedVote, err := cs.scheme.Encrypt(voteValue)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt vote: %v", err)
	}

	// Store encrypted vote using the hex-encoded hash
	homomorphicVotes[choiceHash] = encryptedVote

	pkg := VoteEncryptionPackage{
		HomomorphicVoteData: homomorphicVotes,
		ElectionData:        nil,
		Nonce:               votePayload.Nonce,
	}

	// Debug log
	fmt.Printf("Encrypting vote for choice=%s, hash=%s using %s\n",
		votePayload.Choice, choiceHash, cs.scheme.Name())

	return json.Marshal(pkg)
}

func (cs *CryptoService) DecryptVoteData(encryptedData []byte) ([]byte, error) {
	var pkg VoteEncryptionPackage
	if err := json.Unmarshal(encryptedData, &pkg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vote package: %v", err)
	}

	results := make(map[string]int64)

	// Handle decryption based on scheme type
	switch cs.schemeType {
	case SchemePaillier:
		// Paillier decryption (original implementation)
		for choiceHash, encryptedVote := range pkg.HomomorphicVoteData {
			// Decrypt using Paillier
			decryptedValue, err := cs.scheme.Decrypt(encryptedVote)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt vote for choice %s: %v", choiceHash, err)
			}
			results[choiceHash] = decryptedValue.Int64()
		}

	case SchemeElGamal:
		// ElGamal decryption with vote count extraction
		for choiceHash, encryptedVote := range pkg.HomomorphicVoteData {
			// Decrypt using ElGamal adapter (returns vote count directly)
			decryptedValue, err := cs.scheme.Decrypt(encryptedVote)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt vote for choice %s: %v", choiceHash, err)
			}

			// The discrete log solver in ElGamal adapter takes care of extracting the count
			results[choiceHash] = decryptedValue.Int64()
		}
	}

	return json.Marshal(results)
}

// Modified AddEncryptedVotes to properly handle different encryption schemes
func (cs *CryptoService) AddEncryptedVotes(encryptedVote1, encryptedVote2 []byte) ([]byte, error) {
	var pkg1, pkg2 VoteEncryptionPackage

	if err := json.Unmarshal(encryptedVote1, &pkg1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal first vote: %v", err)
	}
	if err := json.Unmarshal(encryptedVote2, &pkg2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal second vote: %v", err)
	}

	summedVotes := make(map[string][]byte)

	// Combine votes from both packages based on encryption scheme
	for choiceHash, vote1 := range pkg1.HomomorphicVoteData {
		if vote2, exists := pkg2.HomomorphicVoteData[choiceHash]; exists {
			// Use the current scheme for homomorphic addition
			summedVote, err := cs.scheme.Add(vote1, vote2)
			if err != nil {
				return nil, fmt.Errorf("failed to add votes for choice %s: %v", choiceHash, err)
			}
			summedVotes[choiceHash] = summedVote
		} else {
			summedVotes[choiceHash] = vote1
		}
	}

	// Add any choices that only exist in pkg2
	for choiceHash, vote2 := range pkg2.HomomorphicVoteData {
		if _, exists := summedVotes[choiceHash]; !exists {
			summedVotes[choiceHash] = vote2
		}
	}

	// Create the summed package
	sumPkg := VoteEncryptionPackage{
		HomomorphicVoteData: summedVotes,
	}

	return json.Marshal(sumPkg)
}

// The rest of your original CryptoService methods that don't directly deal with encryption/decryption
// can remain mostly unchanged

func (cs *CryptoService) StripVoterData(encryptedData []byte) ([]byte, error) {
	var pkg VoteEncryptionPackage
	if err := json.Unmarshal(encryptedData, &pkg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vote package: %v", err)
	}

	// Keep only necessary data
	anonymizedPkg := VoteEncryptionPackage{
		HomomorphicVoteData: pkg.HomomorphicVoteData,
		Nonce:               pkg.Nonce,
	}

	return json.Marshal(anonymizedPkg)
}

func (cs *CryptoService) GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

func (cs *CryptoService) GenerateNonce() ([]byte, error) {
	nonce := make([]byte, 32)
	_, err := rand.Read(nonce)
	return nonce, err
}

func (cs *CryptoService) ValidateNonce(nonce []byte) error {
	if len(nonce) != 32 {
		return errors.New("nonce must be 32 bytes long")
	}
	return nil
}

func (cs *CryptoService) Sign(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := cs.Keccak256(data)
	return crypto.Sign(hash, privateKey)
}

func (cs *CryptoService) VerifySignature(data, signature []byte, publicKey *ecdsa.PublicKey) bool {
	hash := cs.Keccak256(data)
	sigPublicKey, err := crypto.SigToPub(hash, signature)
	if err != nil {
		return false
	}
	return sigPublicKey.X.Cmp(publicKey.X) == 0 && sigPublicKey.Y.Cmp(publicKey.Y) == 0
}

func (cs *CryptoService) HashData(data []byte) []byte {
	return cs.Keccak256(data)
}

func (cs *CryptoService) FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return crypto.FromECDSAPub(pub)
}

func (cs *CryptoService) Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

func (cs *CryptoService) GetChoiceMapping() map[string]string {
	cs.choiceMappingMu.RLock()
	defer cs.choiceMappingMu.RUnlock()

	mapping := make(map[string]string)
	for k, v := range cs.choiceMapping {
		mapping[k] = v
	}

	return mapping
}

func (cs *CryptoService) storeChoiceMapping(choice string) string {
	cs.choiceMappingMu.Lock()
	defer cs.choiceMappingMu.Unlock()

	// Initialize map if needed
	if cs.choiceMapping == nil {
		cs.choiceMapping = make(map[string]string)
	}

	// Generate hash and store mapping
	choiceHash := cs.hashChoice(choice)
	cs.choiceMapping[choiceHash] = choice

	fmt.Printf("Stored mapping: hash=%s -> choice=%s\n", choiceHash, choice)
	return choiceHash
}

// Helper function to get the keys file path
func (cs *CryptoService) getKeysFilePath() string {
	return filepath.Join(cs.storagePath, "paillier_keys.json")
}

// serializePrivateKey converts the private key to a serializable format.
func serializePrivateKey(key *paillier.PrivateKey) ([]byte, error) {
	// Use the key's built-in marshalling logic if available, or serialize the key components manually.
	return json.Marshal(key)
}

// deserializePrivateKey reconstructs the private key from serialized data.
func deserializePrivateKey(data []byte) (*paillier.PrivateKey, error) {
	// Reconstruct the private key from the serialized data
	var privKey paillier.PrivateKey
	err := json.Unmarshal(data, &privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private key: %v", err)
	}
	return &privKey, nil
}

// These functions can remain for backward compatibility
func (cs *CryptoService) loadPaillierKeys() (*PaillierKeyPair, error) {
	keysFile := cs.getKeysFilePath()
	data, err := os.ReadFile(keysFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys file: %v", err)
	}

	privKey, err := deserializePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Paillier private key: %v", err)
	}

	return &PaillierKeyPair{
		PublicKey:  &privKey.PublicKey,
		PrivateKey: privKey,
	}, nil
}

func (cs *CryptoService) generateAndSavePaillierKeys() (*PaillierKeyPair, error) {
	// Generate a new key pair
	privKey, err := paillier.GenerateKey(rand.Reader, cs.keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Paillier key: %v", err)
	}

	// Serialize the private key
	data, err := serializePrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Paillier private key: %v", err)
	}

	// Save the serialized private key to file
	keysFile := cs.getKeysFilePath()
	if err := os.MkdirAll(filepath.Dir(keysFile), 0700); err != nil {
		return nil, fmt.Errorf("failed to create keys directory: %v", err)
	}

	if err := os.WriteFile(keysFile, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to save Paillier keys: %v", err)
	}

	return &PaillierKeyPair{
		PublicKey:  &privKey.PublicKey,
		PrivateKey: privKey,
	}, nil
}

// GetCurrentScheme returns the current encryption scheme
func (cs *CryptoService) GetCurrentScheme() HomomorphicEncryptionScheme {
	return cs.scheme
}

// GetSchemeType returns the current scheme type
func (cs *CryptoService) GetSchemeType() SchemeType {
	return cs.schemeType
}

// SwitchScheme changes the encryption scheme
// Note: This should be used carefully as it will affect decryption of existing data
func (cs *CryptoService) SwitchScheme(schemeType SchemeType, keySize int) error {
	cs.schemeType = schemeType
	cs.keySize = keySize

	var err error
	switch schemeType {
	case SchemePaillier:
		err = cs.initializePaillier()
	case SchemeElGamal:
		err = cs.initializeElGamal()
	default:
		return fmt.Errorf("unsupported encryption scheme: %s", schemeType)
	}

	return err
}
