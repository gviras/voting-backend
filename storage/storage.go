// File: storage/storage.go
package storage

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"voting-backend/models"
)

type BlockchainStorage struct {
	dataDir string
	mutex   sync.RWMutex
}

// Add a struct to help with file sorting
type chainFile struct {
	path      string
	timestamp int64
}

type chainFiles []chainFile

func (f chainFiles) Len() int           { return len(f) }
func (f chainFiles) Less(i, j int) bool { return f[i].timestamp < f[j].timestamp }
func (f chainFiles) Swap(i, j int)      { f[i], f[j] = f[j], f[i] }

func New(dataDir string) (*BlockchainStorage, error) {
	absPath, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %v", err)
	}

	if err := os.MkdirAll(absPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}

	return &BlockchainStorage{
		dataDir: absPath,
	}, nil
}

// Helper function to get the latest file from a pattern
func (s *BlockchainStorage) getLatestFile(pattern string) (string, error) {
	files, err := filepath.Glob(filepath.Join(s.dataDir, pattern))
	if err != nil {
		return "", fmt.Errorf("failed to list files: %v", err)
	}

	if len(files) == 0 {
		return "", nil
	}

	var chainFiles chainFiles
	for _, file := range files {
		// Extract timestamp from filename
		base := filepath.Base(file)
		parts := strings.Split(base, "_")
		if len(parts) >= 3 {
			timestampStr := strings.TrimSuffix(parts[2], ".json")
			timestamp, err := time.Parse("20060102150405", timestampStr)
			if err != nil {
				log.Printf("Warning: Invalid timestamp in filename %s: %v", base, err)
				continue
			}
			chainFiles = append(chainFiles, chainFile{
				path:      file,
				timestamp: timestamp.Unix(),
			})
		}
	}

	if len(chainFiles) == 0 {
		return "", nil
	}

	// Sort files by timestamp
	sort.Sort(chainFiles)

	// Return the most recent file
	return chainFiles[len(chainFiles)-1].path, nil
}

func (s *BlockchainStorage) LoadLatestDKBChain() ([]models.DistributedKeyBlock, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	latestFile, err := s.getLatestFile("dkb_chain_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to get latest DKB file: %v", err)
	}

	if latestFile == "" {
		return nil, nil
	}

	file, err := os.Open(latestFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", latestFile, err)
	}
	defer file.Close()

	var chain []models.DistributedKeyBlock
	if err := json.NewDecoder(file).Decode(&chain); err != nil {
		return nil, fmt.Errorf("failed to decode chain from %s: %v", latestFile, err)
	}

	log.Printf("Loaded DKB chain with %d blocks from %s", len(chain), latestFile)
	return chain, nil
}

func (s *BlockchainStorage) LoadLatestEVBChain() ([]models.EncryptedVoteBlock, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	latestFile, err := s.getLatestFile("evb_chain_*.json")
	if err != nil {
		return nil, fmt.Errorf("failed to get latest EVB file: %v", err)
	}

	if latestFile == "" {
		return nil, nil
	}

	file, err := os.Open(latestFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", latestFile, err)
	}
	defer file.Close()

	var chain []models.EncryptedVoteBlock
	if err := json.NewDecoder(file).Decode(&chain); err != nil {
		return nil, fmt.Errorf("failed to decode chain from %s: %v", latestFile, err)
	}

	log.Printf("Loaded EVB chain with %d blocks from %s", len(chain), latestFile)
	return chain, nil
}

func (s *BlockchainStorage) SaveDKBChain(chain []models.DistributedKeyBlock) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(chain) == 0 {
		return fmt.Errorf("cannot save empty chain")
	}

	// Use formatted timestamp for better file sorting
	timestamp := time.Now().Format("20060102150405") // YYYYMMDDhhmmss
	filename := filepath.Join(s.dataDir, fmt.Sprintf("dkb_chain_%s.json", timestamp))

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(chain); err != nil {
		return fmt.Errorf("failed to encode chain: %v", err)
	}

	// Cleanup old files
	if err := s.cleanupOldFiles("dkb_chain_*.json", 5); err != nil {
		log.Printf("Warning: Failed to cleanup old DKB files: %v", err)
	}

	log.Printf("Saved DKB chain with %d blocks to %s", len(chain), filename)
	return nil
}

func (s *BlockchainStorage) SaveEVBChain(chain []models.EncryptedVoteBlock) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if len(chain) == 0 {
		log.Printf("Cannot save an empty chain")
		return fmt.Errorf("cannot save empty chain")
	}

	// Log before file creation
	log.Printf("Preparing to save EVB chain with %d blocks", len(chain))

	timestamp := time.Now().Format("20060102150405") // YYYYMMDDhhmmss
	filename := filepath.Join(s.dataDir, fmt.Sprintf("evb_chain_%s.json", timestamp))

	// Log before creating the file
	log.Printf("Creating file: %s", filename)
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("Failed to create file: %v", err)
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer file.Close()

	log.Printf("Encoding chain data...")
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	if err := encoder.Encode(chain); err != nil {
		log.Printf("Failed to encode chain: %v", err)
		return fmt.Errorf("failed to encode chain: %v", err)
	}

	log.Printf("Chain data saved successfully to %s", filename)

	// Cleanup old files
	log.Printf("Starting cleanup of old files...")
	if err := s.cleanupOldFiles("evb_chain_*.json", 5); err != nil {
		log.Printf("Warning: Failed to cleanup old EVB files: %v", err)
	}

	log.Printf("EVB chain save operation completed")
	return nil
}

func (s *BlockchainStorage) cleanupOldFiles(pattern string, keep int) error {
	files, err := filepath.Glob(filepath.Join(s.dataDir, pattern))
	if err != nil {
		return err
	}

	if len(files) <= keep {
		return nil
	}

	var chainFiles chainFiles
	for _, file := range files {
		base := filepath.Base(file)
		parts := strings.Split(base, "_")
		if len(parts) >= 3 {
			timestampStr := strings.TrimSuffix(parts[2], ".json")
			timestamp, err := time.Parse("20060102150405", timestampStr)
			if err != nil {
				log.Printf("Warning: Invalid timestamp in filename %s: %v", base, err)
				continue
			}
			chainFiles = append(chainFiles, chainFile{
				path:      file,
				timestamp: timestamp.Unix(),
			})
		}
	}

	if len(chainFiles) <= keep {
		return nil
	}

	// Sort files by timestamp
	sort.Sort(chainFiles)

	// Remove older files, keeping the most recent 'keep' files
	for i := 0; i < len(chainFiles)-keep; i++ {
		if err := os.Remove(chainFiles[i].path); err != nil {
			log.Printf("Warning: Failed to remove old file %s: %v", chainFiles[i].path, err)
		} else {
			log.Printf("Removed old chain file: %s", chainFiles[i].path)
		}
	}

	return nil
}
