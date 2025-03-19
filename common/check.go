package common

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// CheckLocal checks if a password exists in a common password list file
func CheckLocal(password, filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == password {
			return true
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading file: %v\n", err)
	}

	return false
}

// CheckOnline checks if a password exists in an online password list
func CheckOnline(password, url string) bool {
	// Get the content from the URL
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error fetching URL: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: Received status code %d\n", resp.StatusCode)
		return false
	}

	// Read and check line by line without storing the entire file
	reader := bufio.NewReader(resp.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			fmt.Printf("Error reading response: %v\n", err)
			return false
		}

		if strings.TrimSpace(line) == password {
			return true
		}

		if err == io.EOF {
			break
		}
	}

	return false
} 