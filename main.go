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
	// Define command-line flags
	passwordFlag := flag.String("p", "", "Password to analyze")
	flag.Parse()

	passwordInput := *passwordFlag

	// If no password provided via flag, prompt user for input
	if passwordInput == "" {
		passwordInput = utils.GetPasswordInput()
	}

	// Basic validation
	if passwordInput == "" {
		fmt.Println("Error: Password cannot be empty")
		os.Exit(1)
	}

	// Analyze the password
	length, hasLower, hasUpper, hasDigit, hasSpecial := password.AnalyzePassword(passwordInput)
	
	// Calculate and display password strength
	strength := password.GetStrength(passwordInput, length, hasLower, hasUpper, hasDigit, hasSpecial)
	fmt.Printf("\n🔍 Password Analysis:\n")
	fmt.Printf("Length: %d characters\n", length)
	fmt.Printf("Contains lowercase letters: %t\n", hasLower)
	fmt.Printf("Contains uppercase letters: %t\n", hasUpper)
	fmt.Printf("Contains digits: %t\n", hasDigit)
	fmt.Printf("Contains special characters: %t\n", hasSpecial)
	fmt.Printf("Strength rating: %s\n", strength)

	// Check if user wants to check against common passwords
	if utils.AskYesNo("Do you want to check against common passwords? (y/n)") {
		checkType := utils.AskOption("Choose check type:", []string{"Local file", "Online URL"})
		
		var isCommon bool
		if checkType == "Local file" {
			filePath := utils.AskInput("Enter path to password file:")
			isCommon = common.CheckLocal(passwordInput, filePath)
		} else {
			url := utils.AskInput("Enter URL of password list:")
			isCommon = common.CheckOnline(passwordInput, url)
		}
		
		if isCommon {
			fmt.Println("\n⚠️ WARNING: This password appears in common password lists!")
			fmt.Println("It is highly recommended to choose a different password.")
		} else {
			fmt.Println("\n✅ Good news! Your password was not found in the common password list.")
		}
	}

	// Hash type selection
	fmt.Println("\n🔐 Hash Algorithm Selection:")
	fmt.Println("Different hash algorithms have different cracking speeds.")
	fmt.Println("Fast hashes (MD5, SHA-1, SHA-256) are quicker to crack.")
	fmt.Println("Slow hashes (bcrypt) are designed to be more resistant to cracking attempts.")
	
	hashOptions := hash.GetHashOptions()
	selectedHash := utils.AskOption("Select a hash algorithm:", hashOptions)
	
	fmt.Printf("\nSelected hash algorithm: %s\n", selectedHash)
	
	// Calculate character set size and possible combinations
	charsetSize := password.CharsetSize(hasLower, hasUpper, hasDigit, hasSpecial)
	combinations := password.CalculateCombinations(length, charsetSize)
	
	fmt.Printf("\n📊 Password Complexity:\n")
	fmt.Printf("Character set size: %d\n", charsetSize)
	fmt.Printf("Possible combinations: %s\n", combinations.String())
	
	// System selection and hash speed determination
	fmt.Println("\n💻 System Selection:")
	fmt.Println("Select the type of system you want to simulate for password cracking:")
	systemOptions := []string{"Slow PC", "Normal PC", "High-end GPU"}
	selectedSystem := utils.AskOption("Choose system type:", systemOptions)
	
	// Use predefined hash speeds based on system type
	hashSpeed := systemHashSpeeds[selectedSystem][selectedHash]
	fmt.Printf("\n📝 Using estimated hash speed for %s: %d hashes/second for %s\n", selectedSystem, hashSpeed, selectedHash)
	
	// Ask if user wants to benchmark
	if utils.AskYesNo("\nDo you want to benchmark your actual system's hash speed instead? (y/n)") {
		// Run benchmark
		result := hash.RunBenchmark(selectedHash)
		hashSpeed = result.HashesPerSecond
		fmt.Printf("\n🚀 Benchmark Results:\n")
		fmt.Printf("Your system can compute %d %s hashes per second\n", hashSpeed, selectedHash)
	}
	
	// Estimate crack time
	timeString, timeUnit, _ := password.EstimateCrackTime(combinations, hashSpeed)
	
	fmt.Printf("\n⏱️ Cracking Time Estimation:\n")
	fmt.Printf("Estimated time to crack: %s %s\n", timeString, timeUnit)
	
	// Create a simple interpretation based on the time
	var interpretation string
	seconds := new(big.Float).SetInt64(0)
	
	if timeUnit == "seconds" {
		seconds, _ = new(big.Float).SetString(timeString)
	} else if timeUnit == "minutes" {
		mins, _ := new(big.Float).SetString(timeString)
		seconds = new(big.Float).Mul(mins, big.NewFloat(60))
	} else if timeUnit == "hours" {
		hours, _ := new(big.Float).SetString(timeString)
		seconds = new(big.Float).Mul(hours, big.NewFloat(3600))
	} else if timeUnit == "days" {
		days, _ := new(big.Float).SetString(timeString)
		seconds = new(big.Float).Mul(days, big.NewFloat(86400))
	} else if timeUnit == "years" {
		years, _ := new(big.Float).SetString(timeString)
		seconds = new(big.Float).Mul(years, big.NewFloat(31557600))
	}
	
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
	
	fmt.Printf("Assessment: %s\n", interpretation)
	
	// Sample hash output
	hashFunction := hash.Types[selectedHash]
	passwordBytes := []byte(passwordInput)
	hashedPassword := hashFunction(passwordBytes)
	
	fmt.Printf("\nSample hash output (%s): %x\n", selectedHash, hashedPassword)
} 