package password

// GetStrength determines the strength rating of a password
func GetStrength(password string, length int, hasLower, hasUpper, hasDigit, hasSpecial bool) string {
	// Count the character types used
	charTypes := 0
	if hasLower {
		charTypes++
	}
	if hasUpper {
		charTypes++
	}
	if hasDigit {
		charTypes++
	}
	if hasSpecial {
		charTypes++
	}

	// Basic strength rating based on length and character diversity
	if length < 8 {
		return "Weak"
	} else if length < 10 {
		if charTypes >= 3 {
			return "Medium"
		}
		return "Weak"
	} else if length < 12 {
		if charTypes >= 3 {
			return "Strong"
		}
		return "Medium"
	} else {
		if charTypes >= 4 {
			return "Very Strong"
		} else if charTypes >= 3 {
			return "Strong"
		}
		return "Medium"
	}
} 