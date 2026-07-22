package analyzer

import (
	"bufio"
	"os"
)

// Chunker splits a file into smaller, manageable chunks for LLM analysis.
func Chunker(filePath string, chunkSize int) ([][]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var chunks [][]string
	var currentChunk []string
	scanner := bufio.NewScanner(file)
	lineCount := 0

	for scanner.Scan() {
		currentChunk = append(currentChunk, scanner.Text())
		lineCount++
		if lineCount >= chunkSize {
			chunks = append(chunks, currentChunk)
			currentChunk = nil
			lineCount = 0
		}
	}
	if len(currentChunk) > 0 {
		chunks = append(chunks, currentChunk)
	}
	return chunks, scanner.Err()
}
