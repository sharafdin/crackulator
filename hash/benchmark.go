package hash

import (
	"fmt"
	"time"
)

// BenchmarkResult holds the benchmark data
type BenchmarkResult struct {
	HashType   string
	HashesPerSecond int64
}

// RunBenchmark performs a benchmark test for the given hash type
func RunBenchmark(hashType string) BenchmarkResult {
	iterations := 100000 // 100k iterations for fast hashes
	if hashType == "bcrypt" {
		iterations = 10 // bcrypt is much slower, so use fewer iterations
	}

	// Get the hash function
	hashFunc := Types[hashType]
	if hashFunc == nil {
		return BenchmarkResult{
			HashType:   hashType,
			HashesPerSecond: 0,
		}
	}

	fmt.Printf("Running benchmark for %s with %d iterations...\n", hashType, iterations)
	
	// Sample data to hash during benchmark
	data := []byte("benchmark_password_sample")
	
	// Start timing
	startTime := time.Now()
	
	// Run the hash function the specified number of times
	for i := 0; i < iterations; i++ {
		hashFunc(data)
	}
	
	// Calculate elapsed time
	elapsedTime := time.Since(startTime)
	
	// Calculate hashes per second
	hashesPerSecond := int64(float64(iterations) / elapsedTime.Seconds())
	
	return BenchmarkResult{
		HashType:   hashType,
		HashesPerSecond: hashesPerSecond,
	}
} 