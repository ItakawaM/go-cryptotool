package analyze

import "fmt"

type Analyzer interface {
	AnalyzeFile(inputFilePath string) ([]AnalysisResult, error)
	AnalyzeBuffer(buffer []byte) ([]AnalysisResult, error)
}

type AnalysisResult struct {
	Key          byte
	ChiScore     float64
	EnglishScore float64
}

func (ar AnalysisResult) String() string {
	return fmt.Sprintf("[%02d]: %.3f | %.3f", ar.Key, ar.ChiScore, ar.EnglishScore)
}
