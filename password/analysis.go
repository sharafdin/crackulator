package password

// AnalyzePassword checks password characteristics
func AnalyzePassword(password string) (int, bool, bool, bool, bool) {
	length := len(password)
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'a' <= char && char <= 'z':
			hasLower = true
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case '0' <= char && char <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	return length, hasLower, hasUpper, hasDigit, hasSpecial
} 