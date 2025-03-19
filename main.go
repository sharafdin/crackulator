/*
===============================================
  Crackulator - Password Cracking Time Estimator
===============================================
  
🔹 Author: Mr Sharafdin  
🔹 Email: thesharafdin@gmail.com  
🔹 GitHub: github.com/sharafdin/crackulator  

📌 Description:
Crackulator is a CLI tool that analyzes passwords, checks their strength,  
compares them against common password lists, and estimates the time required  
to crack them using different hashing algorithms.
*/

package main

import (
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/sharafdin/crackulator/common"
	"github.com/sharafdin/crackulator/hash"
	"github.com/sharafdin/crackulator/password"
	"github.com/sharafdin/crackulator/utils"
)

// System type hash speeds in hashes per second
var systemHashSpeeds = map[string]map[string]int64{
	"Slow PC": {
		"MD5":     5000000,    // 5 million/sec
		"SHA-1":   3000000,    // 3 million/sec
		"SHA-256": 1000000,    // 1 million/sec
		"bcrypt":  3,          // 3/sec
	},
	"Normal PC": {
		"MD5":     500000000,  // 500 million/sec
		"SHA-1":   200000000,  // 200 million/sec
		"SHA-256": 100000000,  // 100 million/sec
		"bcrypt":  5,          // 5/sec
	},
	"High-end GPU": {
		"MD5":     10000000000, // 10 billion/sec
		"SHA-1":   5000000000,  // 5 billion/sec
		"SHA-256": 1000000000,  // 1 billion/sec
		"bcrypt":  10,          // 10/sec (GPUs aren't great for bcrypt)
	},
}

func main() {
	// Clear the screen and print welcome message
	fmt.Print("\033[H\033[2J") // ANSI escape code to clear screen
	fmt.Println("=================================================================")
	fmt.Println("  🔐 Welcome to Crackulator - Password Cracking Time Estimator 🔐")
	fmt.Println("=================================================================")
	fmt.Println()

	// Define command-line flags
	passwordFlag := flag.String("p", "", "Password to analyze")
	flag.Parse()

	passwordInput := *passwordFlag

	// === DATA COLLECTION PHASE ===
	
	// 1. Get password input
	if passwordInput == "" {
		passwordInput = utils.GetPasswordInput()
	}

	// Basic validation
	if passwordInput == "" {
		fmt.Println("Error: Password cannot be empty")
		os.Exit(1)
	}

	// 2. Analyze the password
	length, hasLower, hasUpper, hasDigit, hasSpecial := password.AnalyzePassword(passwordInput)
	strength := password.GetStrength(passwordInput, length, hasLower, hasUpper, hasDigit, hasSpecial)
	
	// 3. Check for common password
	checkCommonPassword := utils.AskYesNo("Do you want to check against common passwords? (y/n)")
	
	var checkType, filePath, url string
	var isCommon bool
	
	if checkCommonPassword {
		checkType = utils.AskOption("Choose check type:", []string{"Local file", "Online URL"})
		
		if checkType == "Local file" {
			filePath = utils.AskInput("Enter path to password file:")
		} else {
			url = utils.AskInput("Enter URL of password list:")
		}
	}

	// 4. Hash algorithm selection
	fmt.Println("\n🔐 Hash Algorithm Selection:")
	fmt.Println("Different hash algorithms have different cracking speeds.")
	fmt.Println("Fast hashes (MD5, SHA-1, SHA-256) are quicker to crack.")
	fmt.Println("Slow hashes (bcrypt) are designed to be more resistant to cracking attempts.")
	
	hashOptions := hash.GetHashOptions()
	selectedHash := utils.AskOption("Select a hash algorithm:", hashOptions)
	
	// 5. System selection
	fmt.Println("\n💻 System Selection:")
	fmt.Println("Select the type of system you want to simulate for password cracking:")
	systemOptions := []string{"Slow PC", "Normal PC", "High-end GPU"}
	selectedSystem := utils.AskOption("Choose system type:", systemOptions)
	
	// 6. Benchmarking option
	runBenchmark := utils.AskYesNo("\nDo you want to benchmark your actual system's hash speed? (y/n)")
	
	// === PROCESSING PHASE ===
	
	// 1. Calculate character set size and possible combinations
	charsetSize := password.CharsetSize(hasLower, hasUpper, hasDigit, hasSpecial)
	combinations := password.CalculateCombinations(length, charsetSize)
	
	// 2. Perform common password check if requested
	if checkCommonPassword {
		if checkType == "Local file" {
			isCommon = common.CheckLocal(passwordInput, filePath)
		} else {
			isCommon = common.CheckOnline(passwordInput, url)
		}
	}
	
	// 3. Determine hash speed (theoretical and benchmarked)
	theoreticalHashSpeed := systemHashSpeeds[selectedSystem][selectedHash]
	
	// Variables for benchmarked values
	var benchmarkedHashSpeed int64
	var benchmarkResult hash.BenchmarkResult
	
	if runBenchmark {
		fmt.Println("\nRunning benchmark, please wait...")
		benchmarkResult = hash.RunBenchmark(selectedHash)
		benchmarkedHashSpeed = benchmarkResult.HashesPerSecond
	}
	
	// 4. Calculate cracking time (for both theoretical and benchmarked speeds)
	theoreticalTimeString, theoreticalTimeUnit, _ := password.EstimateCrackTime(combinations, theoreticalHashSpeed)
	
	// Only calculate benchmarked time if benchmark was run
	var benchmarkedTimeString, benchmarkedTimeUnit string
	if runBenchmark {
		benchmarkedTimeString, benchmarkedTimeUnit, _ = password.EstimateCrackTime(combinations, benchmarkedHashSpeed)
	}
	
	// 5. Create interpretation for theoretical time
	seconds := new(big.Float).SetInt64(0)
	
	if theoreticalTimeUnit == "seconds" {
		seconds, _ = new(big.Float).SetString(theoreticalTimeString)
	} else if theoreticalTimeUnit == "minutes" {
		mins, _ := new(big.Float).SetString(theoreticalTimeString)
		seconds = new(big.Float).Mul(mins, big.NewFloat(60))
	} else if theoreticalTimeUnit == "hours" {
		hours, _ := new(big.Float).SetString(theoreticalTimeString)
		seconds = new(big.Float).Mul(hours, big.NewFloat(3600))
	} else if theoreticalTimeUnit == "days" {
		days, _ := new(big.Float).SetString(theoreticalTimeString)
		seconds = new(big.Float).Mul(days, big.NewFloat(86400))
	} else if theoreticalTimeUnit == "years" {
		years, _ := new(big.Float).SetString(theoreticalTimeString)
		seconds = new(big.Float).Mul(years, big.NewFloat(31557600))
	}
	
	var interpretation string
	if seconds.Cmp(big.NewFloat(60)) < 0 {
		interpretation = "Extremely Weak: This password would be cracked instantly!"
	} else if seconds.Cmp(big.NewFloat(3600)) < 0 { // < 1 hour
		interpretation = "Very Weak: This password would be cracked in minutes!"
	} else if seconds.Cmp(big.NewFloat(86400)) < 0 { // < 1 day
		interpretation = "Weak: This password would be cracked in hours."
	} else if seconds.Cmp(big.NewFloat(604800)) < 0 { // < 1 week
		interpretation = "Moderate: This password would take a few days to crack."
	} else if seconds.Cmp(big.NewFloat(2592000)) < 0 { // < 1 month
		interpretation = "Good: This password would take weeks to crack."
	} else if seconds.Cmp(big.NewFloat(31557600)) < 0 { // < 1 year
		interpretation = "Strong: This password would take months to crack."
	} else if seconds.Cmp(big.NewFloat(315576000)) < 0 { // < 10 years
		interpretation = "Very Strong: This password would take years to crack."
	} else {
		interpretation = "Excellent: This password would take decades or more to crack."
	}
	
	// 6. Generate hash sample
	hashFunction := hash.Types[selectedHash]
	passwordBytes := []byte(passwordInput)
	hashedPassword := hashFunction(passwordBytes)
	
	// === REPORT PHASE ===
	
	// Clear screen again for the report
	fmt.Print("\033[H\033[2J")
	
	// Print header
	fmt.Println("=================================================================")
	fmt.Println("                  🔒 PASSWORD ANALYSIS REPORT 🔒                  ")
	fmt.Println("=================================================================")
	
	// Print password summary
	fmt.Println("\n📋 PASSWORD SUMMARY:")
	fmt.Printf("Password: %s\n", passwordInput)
	fmt.Printf("Length: %d characters\n", length)
	
	// Print character types
	fmt.Println("\n🔤 CHARACTER COMPOSITION:")
	fmt.Printf("Lowercase letters (a-z): %s\n", formatBool(hasLower))
	fmt.Printf("Uppercase letters (A-Z): %s\n", formatBool(hasUpper))
	fmt.Printf("Digits (0-9): %s\n", formatBool(hasDigit))
	fmt.Printf("Special characters: %s\n", formatBool(hasSpecial))
	fmt.Printf("Character set size: %d\n", charsetSize)
	
	// Print strength rating
	fmt.Println("\n💪 STRENGTH ASSESSMENT:")
	fmt.Printf("Basic strength rating: %s\n", strength)
	
	// Print common password check results
	if checkCommonPassword {
		fmt.Println("\n🔍 COMMON PASSWORD CHECK:")
		if isCommon {
			fmt.Println("⚠️  WARNING: This password appears in common password lists!")
			fmt.Println("    It is highly recommended to choose a different password.")
		} else {
			fmt.Println("✅  Good news! Your password was not found in the common password list.")
		}
	}
	
	// Print cracking difficulty
	fmt.Println("\n🔢 BRUTE FORCE COMPLEXITY:")
	fmt.Printf("Possible combinations: %s\n", combinations.String())
	
	// Print hash information
	fmt.Println("\n🔐 HASH INFORMATION:")
	fmt.Printf("Selected algorithm: %s\n", selectedHash)
	fmt.Printf("Selected system: %s\n", selectedSystem)
	fmt.Printf("Theoretical hash speed: %d hashes/second\n", theoreticalHashSpeed)
	
	if runBenchmark {
		fmt.Printf("Your computer's benchmark: %d hashes/second\n", benchmarkedHashSpeed)
	}
	
	fmt.Printf("Sample hash output: %x\n", hashedPassword)
	
	// Print cracking time estimation
	fmt.Println("\n⏱️  CRACKING TIME ESTIMATION:")
	fmt.Printf("For %s (theoretical): %s %s\n", selectedSystem, theoreticalTimeString, theoreticalTimeUnit)
	
	if runBenchmark {
		fmt.Printf("For your computer (benchmarked): %s %s\n", benchmarkedTimeString, benchmarkedTimeUnit)
	}
	
	fmt.Printf("Security assessment: %s\n", interpretation)
	
	fmt.Println("\n=================================================================")
	fmt.Println("                       END OF REPORT                            ")
	fmt.Println("=================================================================")
}

// formatBool returns "Yes" for true and "No" for false
func formatBool(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
} 