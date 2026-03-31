package analyze

import (
	"io"
	"os"
)

type Analyzer interface {
	AnalyzeBuffer(buffer []byte) ([]AnalysisResult, error)
}

type AnalysisResult struct {
	Key      byte
	ChiScore float64
}

func AnalyzeFile(analyzer Analyzer, inputFilepath string) ([]AnalysisResult, error) {
	inFile, err := os.Open(inputFilepath)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()

	buffer := make([]byte, 16*1024) // Read 16KB or less
	n, err := io.ReadFull(inFile, buffer)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	buffer = buffer[:n]

	return analyzer.AnalyzeBuffer(buffer)
}
