package models

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

// Block represents a block in the blockchain
type Block struct {
	Index      uint64 `json:"index"`
	Timestamp  int64  `json:"timestamp"`
	Data       []byte `json:"data"`
	PrevHash   []byte `json:"prev_hash"`
	Hash       []byte `json:"hash"`
	Nonce      uint64 `json:"nonce"`
	Difficulty uint8  `json:"difficulty"`
}

// NewBlock creates a new block and mines it
func NewBlock(index uint64, data []byte, prevHash []byte, difficulty uint8) *Block {
	block := &Block{
		Index:      index,
		Timestamp:  time.Now().Unix(),
		Data:       data,
		PrevHash:   prevHash,
		Difficulty: difficulty,
	}

	//block.Mine()
	block.Hash = block.calculateHash()
	return block
}

// Mine performs proof of work to find a valid hash
func (b *Block) Mine() {
	prefix := make([]byte, b.Difficulty)
	var nonce uint64
	for {
		b.Nonce = nonce
		b.Hash = b.calculateHash()
		if bytes.HasPrefix(b.Hash, prefix) {
			break
		}
		nonce++
		// Add a check for every 1000 attempts to prevent blocking
		if nonce%1000 == 0 {
			time.Sleep(time.Microsecond) // Give other goroutines a chance to run
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

// Validate checks if the block's hash is valid
func (b *Block) Validate() bool {
	prefix := make([]byte, b.Difficulty)
	calculatedHash := b.calculateHash()
	return bytes.Equal(calculatedHash, b.Hash) &&
		bytes.HasPrefix(calculatedHash, prefix)
}

// GetHash returns the block's hash
func (b *Block) GetHash() []byte {
	return b.Hash
}

// GetPrevHash returns the previous block's hash
func (b *Block) GetPrevHash() []byte {
	return b.PrevHash
}

// GetTimestamp returns the block's timestamp
func (b *Block) GetTimestamp() int64 {
	return b.Timestamp
}

// GetIndex returns the block's index
func (b *Block) GetIndex() uint64 {
	return b.Index
}

// GetData returns the block's data
func (b *Block) GetData() []byte {
	return b.Data
}
