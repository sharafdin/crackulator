package password

import (
	"fmt"
	"math/big"
)

// CharsetSize returns the size of the character set used in the password
func CharsetSize(hasLower, hasUpper, hasDigit, hasSpecial bool) int {
	size := 0
	if hasLower {
		size += 26 // a-z
	}
	if hasUpper {
		size += 26 // A-Z
	}
	if hasDigit {
		size += 10 // 0-9
	}
	if hasSpecial {
		size += 33 // Special characters (~33 common ones)
	}
	
	// Ensure at least 1 character in charset
	if size == 0 {
		size = 1
	}
	
	return size
}

// CalculateCombinations computes possible brute-force attempts
func CalculateCombinations(length int, charsetSize int) *big.Int {
	if length <= 0 || charsetSize <= 0 {
		return big.NewInt(0)
	}
	
	// Calculate charsetSize^length
	combinations := big.NewInt(1)
	charsetBig := big.NewInt(int64(charsetSize))
	
	for i := 0; i < length; i++ {
		combinations.Mul(combinations, charsetBig)
	}
	
	return combinations
}

// FormatTime formats a duration in human-readable form
func FormatTime(seconds *big.Float) (string, string, string) {
	// Convert to different time units
	minutes := new(big.Float).Quo(seconds, big.NewFloat(60))
	hours := new(big.Float).Quo(minutes, big.NewFloat(60))
	days := new(big.Float).Quo(hours, big.NewFloat(24))
	years := new(big.Float).Quo(days, big.NewFloat(365.25))
	
	var timeString, timeUnit, timeScale string
	
	switch {
	case seconds.Cmp(big.NewFloat(60)) < 0:
		// Less than a minute
		timeString = formatBigFloat(seconds)
		timeUnit = "seconds"
		timeScale = "seconds"
	case seconds.Cmp(big.NewFloat(3600)) < 0:
		// Less than an hour
		timeString = formatBigFloat(minutes)
		timeUnit = "minutes"
		timeScale = "minutes"
	case seconds.Cmp(big.NewFloat(86400)) < 0:
		// Less than a day
		timeString = formatBigFloat(hours)
		timeUnit = "hours"
		timeScale = "hours"
	case seconds.Cmp(big.NewFloat(31557600)) < 0:
		// Less than a year
		timeString = formatBigFloat(days)
		timeUnit = "days"
		timeScale = "days"
	default:
		// Years or more
		timeString = formatBigFloat(years)
		timeUnit = "years"
		timeScale = "years"
	}
	
	return timeString, timeUnit, timeScale
}

// EstimateCrackTime estimates the time required to crack the password
func EstimateCrackTime(combinations *big.Int, hashesPerSecond int64) (string, string, string) {
	// Avoid division by zero
	if hashesPerSecond <= 0 {
		hashesPerSecond = 1
	}
	
	// Calculate seconds required = combinations / hashes per second
	hashesPerSecondBig := new(big.Float).SetInt64(hashesPerSecond)
	combinationsBig := new(big.Float).SetInt(combinations)
	
	// seconds = combinations / hashesPerSecond
	seconds := new(big.Float).Quo(combinationsBig, hashesPerSecondBig)
	
	return FormatTime(seconds)
}

// Helper function to format big.Float values with reasonable precision
func formatBigFloat(value *big.Float) string {
	// For large values, round to whole number
	if value.Cmp(big.NewFloat(1000)) >= 0 {
		// Round to the nearest integer
		intValue, _ := value.Int(nil)
		return fmt.Sprintf("%d", intValue)
	}
	
	// For medium values, show 2 decimal places
	if value.Cmp(big.NewFloat(10)) >= 0 {
		return fmt.Sprintf("%.2f", value)
	}
	
	// For small values, show 4 decimal places
	return fmt.Sprintf("%.4f", value)
} 