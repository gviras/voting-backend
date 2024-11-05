package models

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

type Block struct {
	Index      uint64 `json:"index"`
	Timestamp  int64  `json:"timestamp"`
	Data       []byte `json:"data"`
	PrevHash   []byte `json:"prev_hash"`
	Hash       []byte `json:"hash"`
	Nonce      uint64 `json:"nonce"`
	Difficulty uint8  `json:"difficulty"` // Number of leading zeros required
}

func NewBlock(index uint64, data []byte, prevHash []byte, difficulty uint8) *Block {
	block := &Block{
		Index:      index,
		Timestamp:  time.Now().Unix(),
		Data:       data,
		PrevHash:   prevHash,
		Difficulty: difficulty,
	}

	block.Mine() // Always perform mining
	return block
}

func (b *Block) Mine() {
	target := make([]byte, b.Difficulty)
	var nonce uint64
	for {
		b.Nonce = nonce
		b.Hash = b.calculateHash()

		// Check if we have enough leading zeros
		if bytes.HasPrefix(b.Hash, target) {
			return
		}

		nonce++
		if nonce%1000 == 0 {
			time.Sleep(time.Microsecond) // Prevent CPU hogging
		}
	}
}

func (b *Block) calculateHash() []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.BigEndian, b.Index)
	binary.Write(buffer, binary.BigEndian, b.Timestamp)
	buffer.Write(b.Data)
	buffer.Write(b.PrevHash)
	binary.Write(buffer, binary.BigEndian, b.Nonce)

	hash := sha256.Sum256(buffer.Bytes())
	return hash[:]
}

func (b *Block) Validate() bool {
	// Verify hash calculation
	calculatedHash := b.calculateHash()
	if !bytes.Equal(calculatedHash, b.Hash) {
		return false
	}

	// Verify difficulty requirement
	target := make([]byte, b.Difficulty)
	return bytes.HasPrefix(calculatedHash, target)
}

// ValidateChain validates the entire blockchain
func ValidateChain(blocks []*Block) bool {
	if len(blocks) == 0 {
		return true
	}

	// Validate genesis block
	if !blocks[0].Validate() {
		return false
	}

	// Validate each subsequent block
	for i := 1; i < len(blocks); i++ {
		currentBlock := blocks[i]
		previousBlock := blocks[i-1]

		// Verify block hash
		if !currentBlock.Validate() {
			return false
		}

		// Verify block links correctly to previous block
		if !bytes.Equal(currentBlock.PrevHash, previousBlock.Hash) {
			return false
		}

		// Verify block index
		if currentBlock.Index != previousBlock.Index+1 {
			return false
		}

		// Verify timestamp is after previous block
		if currentBlock.Timestamp <= previousBlock.Timestamp {
			return false
		}
	}

	return true
}