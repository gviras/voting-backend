package encryption

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/roasbeef/go-go-gadget-paillier"
	"golang.org/x/crypto/sha3"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"voting-backend/models"
)

// VoteEncryptionPackage represents the separated vote and voter data
type VoteEncryptionPackage struct {
	HomomorphicVoteData map[string][]byte `json:"homomorphic_votes"` // Map of encrypted choice identifiers to vote counts
	ElectionData        []byte            `json:"election_data"`     // Election verification data
	Nonce               []byte            `json:"nonce"`             // For vote verification
}

type CryptoService struct {
	paillierPrivateKey *paillier.PrivateKey
	PaillierPublicKey  *paillier.PublicKey
	choiceMapping      map[string]string // maps hash to candidate name
	choiceMappingMu    sync.RWMutex      // separate mutex for choice mapping
	storagePath        string
}

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

func (cs *CryptoService) GetChoiceMapping() map[string]string {
	cs.choiceMappingMu.RLock()
	defer cs.choiceMappingMu.RUnlock()

	// Make a copy to prevent concurrent map access
	mapping := make(map[string]string)
	for k, v := range cs.choiceMapping {
		mapping[k] = v
	}

	// Debug log current mapping
	fmt.Printf("Current choice mapping: %+v\n", mapping)
	return mapping
}

func (cs *CryptoService) DumpChoiceMapping() {
	cs.choiceMappingMu.RLock()
	defer cs.choiceMappingMu.RUnlock()

	fmt.Println("\n=== Choice Mapping Dump ===")
	for hash, choice := range cs.choiceMapping {
		fmt.Printf("Hash: %s -> Choice: %s\n", hash, choice)
	}
	fmt.Println("========================\n")
}

func (cs *CryptoService) GetChoiceMappingMu() *sync.RWMutex {
	return &cs.choiceMappingMu
}

// NewCryptoService initializes a new CryptoService with Paillier keys
func NewCryptoService(storagePath string) (*CryptoService, error) {
	// Debug log the storage path being used
	fmt.Printf("Initializing CryptoService with storage path: %s\n", storagePath)

	// Ensure the directory for the storage path exists
	if err := os.MkdirAll(storagePath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %v", err)
	}

	cs := &CryptoService{storagePath: storagePath}

	// Get the expected keys file path
	keysFile := cs.getKeysFilePath()
	fmt.Printf("Looking for Paillier keys file at: %s\n", keysFile)

	// Check if the file exists
	if _, err := os.Stat(keysFile); errors.Is(err, os.ErrNotExist) {
		// If the file does not exist, generate and save new keys
		fmt.Println("Paillier keys file not found, generating new keys...")
		keys, err := cs.generateAndSavePaillierKeys()
		if err != nil {
			return nil, fmt.Errorf("failed to generate and save Paillier keys: %v", err)
		}

		cs.paillierPrivateKey = keys.PrivateKey
		cs.PaillierPublicKey = keys.PublicKey
		fmt.Println("New Paillier keys successfully generated and saved.")
		return cs, nil
	} else if err != nil {
		// Handle unexpected errors when checking the file
		return nil, fmt.Errorf("failed to check Paillier keys file: %v", err)
	}

	// If the file exists, load the keys
	fmt.Println("Paillier keys file found, loading keys...")
	keys, err := cs.loadPaillierKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to load Paillier keys: %v", err)
	}

	cs.paillierPrivateKey = keys.PrivateKey
	cs.PaillierPublicKey = keys.PublicKey
	fmt.Println("Paillier keys successfully loaded.")
	return cs, nil
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

// EncryptVoteData encrypts votes with homomorphic encryption and separates voter data
func (cs *CryptoService) EncryptVoteData(votePayload models.VotePayload) ([]byte, error) {
	// Hash and store choice mapping
	choiceHash := cs.storeChoiceMapping(votePayload.Choice)

	homomorphicVotes := make(map[string][]byte)

	// Encrypt vote value
	voteValue := int64ToBytes(1)
	encryptedVote, err := paillier.Encrypt(cs.PaillierPublicKey, voteValue)
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
	fmt.Printf("Encrypting vote for choice=%s, hash=%s\n",
		votePayload.Choice, choiceHash)

	return json.Marshal(pkg)
}

func (cs *CryptoService) DecryptVoteData(encryptedData []byte) ([]byte, error) {
	var pkg VoteEncryptionPackage
	if err := json.Unmarshal(encryptedData, &pkg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vote package: %v", err)
	}

	results := make(map[string]int)

	for choiceHash, encryptedVote := range pkg.HomomorphicVoteData {
		// Decrypt to get the plaintext value
		decryptedValue, err := paillier.Decrypt(cs.paillierPrivateKey, encryptedVote)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt vote for choice %s: %v", choiceHash, err)
		}

		// Convert the decrypted value to an integer
		value := new(big.Int).SetBytes(decryptedValue)

		// Since we're only adding 1s, the result should be a small integer
		if value.BitLen() > 32 { // Sanity check
			return nil, fmt.Errorf("unexpected large value after decryption")
		}

		results[choiceHash] = int(value.Int64())
	}

	return json.Marshal(results)
}

func (cs *CryptoService) AddEncryptedVotes(encryptedVote1, encryptedVote2 []byte) ([]byte, error) {
	var pkg1, pkg2 VoteEncryptionPackage

	if err := json.Unmarshal(encryptedVote1, &pkg1); err != nil {
		return nil, fmt.Errorf("failed to unmarshal first vote: %v", err)
	}
	if err := json.Unmarshal(encryptedVote2, &pkg2); err != nil {
		return nil, fmt.Errorf("failed to unmarshal second vote: %v", err)
	}

	summedVotes := make(map[string][]byte)

	// Combine votes from both packages
	for choiceHash, vote1 := range pkg1.HomomorphicVoteData {
		if vote2, exists := pkg2.HomomorphicVoteData[choiceHash]; exists {
			// Use Paillier homomorphic addition
			summedVotes[choiceHash] = paillier.AddCipher(cs.PaillierPublicKey, vote1, vote2)
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

	sumPkg := VoteEncryptionPackage{
		HomomorphicVoteData: summedVotes,
	}

	return json.Marshal(sumPkg)
}

// StripVoterData removes voter-specific data for anonymization
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

func int64ToBytes(val int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(val))
	return buf
}

func bytesToInt64(bytes []byte) int64 {
	// Convert big-endian byte slice to big.Int
	bigInt := new(big.Int).SetBytes(bytes)

	// Convert to int64, handling potential overflow
	if !bigInt.IsInt64() {
		log.Printf("Warning: number %s is too large for int64, truncating", bigInt.String())
		// If too large, get the last 64 bits
		mask := new(big.Int).Lsh(big.NewInt(1), 64)
		mask.Sub(mask, big.NewInt(1))
		bigInt.And(bigInt, mask)
	}

	return bigInt.Int64()
}

// Alternative version that explicitly checks for negative numbers
func bytesToInt64Safe(bytes []byte) (int64, error) {
	bigInt := new(big.Int).SetBytes(bytes)

	// Check if the number can fit in int64
	if !bigInt.IsInt64() {
		return 0, fmt.Errorf("number %s is too large for int64", bigInt.String())
	}

	// Get the int64 value
	value := bigInt.Int64()

	// Ensure the value is non-negative (as vote counts should be positive)
	if value < 0 {
		return 0, fmt.Errorf("invalid negative value: %d", value)
	}

	return value, nil
}

// GenerateKeyPair generates a new ECDSA key pair
func (cs *CryptoService) GenerateKeyPair() (*ecdsa.PrivateKey, error) {
	return crypto.GenerateKey()
}

// GenerateNonce generates a cryptographic random nonce
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

// Sign creates a digital signature of data using the private key
func (cs *CryptoService) Sign(data []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := cs.Keccak256(data)
	return crypto.Sign(hash, privateKey)
}

// VerifySignature verifies the signature of data using the public key
func (cs *CryptoService) VerifySignature(data, signature []byte, publicKey *ecdsa.PublicKey) bool {
	hash := cs.Keccak256(data)
	sigPublicKey, err := crypto.SigToPub(hash, signature)
	if err != nil {
		return false
	}
	return sigPublicKey.X.Cmp(publicKey.X) == 0 && sigPublicKey.Y.Cmp(publicKey.Y) == 0
}

// HashData creates a Keccak256 hash of the provided data
func (cs *CryptoService) HashData(data []byte) []byte {
	return cs.Keccak256(data)
}

// FromECDSAPub serializes the public key to bytes
func (cs *CryptoService) FromECDSAPub(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return crypto.FromECDSAPub(pub)
}

// Keccak256 computes a Keccak-256 hash
func (cs *CryptoService) Keccak256(data ...[]byte) []byte {
	d := sha3.NewLegacyKeccak256()
	for _, b := range data {
		d.Write(b)
	}
	return d.Sum(nil)
}

// PublicKeyFromBytes converts bytes to an ECDSA public key
func (cs *CryptoService) PublicKeyFromBytes(pubKeyBytes []byte) (*ecdsa.PublicKey, error) {
	if len(pubKeyBytes) == 0 {
		return nil, fmt.Errorf("empty public key bytes")
	}

	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %v", err)
	}

	return pubKey, nil
}

// VerifyPublicKeyHash verifies a public key against its expected hash
func (cs *CryptoService) VerifyPublicKeyHash(publicKey *ecdsa.PublicKey, expectedHash []byte) bool {
	if publicKey == nil {
		return false
	}

	pubKeyBytes := cs.FromECDSAPub(publicKey)
	actualHash := cs.Keccak256(pubKeyBytes)

	return bytes.Equal(actualHash, expectedHash)
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

// getKeysFilePath returns the full path for storing Paillier keys.
func (cs *CryptoService) getKeysFilePath() string {
	return filepath.Join(cs.storagePath, "paillier_keys.json")
}

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

// generateAndSavePaillierKeys generates new Paillier keys and saves them to a file.
func (cs *CryptoService) generateAndSavePaillierKeys() (*PaillierKeyPair, error) {
	// Generate a new key pair
	privKey, err := paillier.GenerateKey(rand.Reader, 2048)
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
