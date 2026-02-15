package benchmark

import (
	"fmt"
	"runtime"
	"time"
)

func getMemoryUsage() string {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	return fmt.Sprintf("Alloc = %v MB\nTotalAlloc = %v MB\nSys = %v MB\nNumGC = %v\n", bToMb(stats.Alloc), bToMb(stats.TotalAlloc), bToMb(stats.Sys), bToMb(uint64(stats.NumGC)))

}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func MeasurePerformance(name string) func() {
	start := time.Now()
	return func() {
		fmt.Printf("\nGO-CRYPTOTOOL PERFORMANCE\n====================================\n%s took %s\n%s", name, time.Since(start), getMemoryUsage())
	}
}
