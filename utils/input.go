package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// GetPasswordInput prompts the user to enter a password
func GetPasswordInput() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter password to analyze: ")
	password, _ := reader.ReadString('\n')
	return strings.TrimSpace(password)
}

// AskYesNo asks a yes/no question and returns true for yes
func AskYesNo(question string) bool {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(question + " ")
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		
		if answer == "y" || answer == "yes" {
			return true
		} else if answer == "n" || answer == "no" {
			return false
		}
		
		fmt.Println("Please answer with 'y' or 'n'")
	}
}

// AskOption asks the user to choose from a list of options
func AskOption(question string, options []string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println(question)
	
	for i, option := range options {
		fmt.Printf("%d. %s\n", i+1, option)
	}
	
	for {
		fmt.Print("Enter your choice (1-" + fmt.Sprint(len(options)) + "): ")
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(answer)
		
		// Try to convert to int
		var choice int
		_, err := fmt.Sscanf(answer, "%d", &choice)
		
		if err == nil && choice >= 1 && choice <= len(options) {
			return options[choice-1]
		}
		
		fmt.Println("Invalid choice. Please try again.")
	}
}

// AskInput asks the user for text input
func AskInput(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt + " ")
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
} 