# Crackulator

A CLI tool for password strength analysis and cracking time estimation.

## Features

- 🔒 Password strength analysis
- 🔍 Check against common password lists
- ⏱️ Estimate password cracking time
- 🚀 Benchmark system hash performance
- 📊 Calculate total password combinations

## Project Structure

```
crackulator/
├── common/         # Common password checking functionality
├── hash/           # Hash algorithms and benchmarking
├── password/       # Password analysis and estimation
├── utils/          # Utility functions
├── go.mod          # Go module definition
├── main.go         # Main application
├── Dockerfile      # Docker configuration
└── README.md       # Documentation
```

## Installation

### Standard Installation

```bash
# Clone the repository
git clone https://github.com/sharafdin/crackulator.git

# Navigate to the project directory
cd crackulator

# Build the project
go build
```

### Docker Installation

```bash
# Clone the repository
git clone https://github.com/sharafdin/crackulator.git

# Navigate to the project directory
cd crackulator

# Build the Docker image
docker build -t crackulator .
```

## Usage

### Standard Usage

```bash
# Analyze a password interactively
./crackulator

# Analyze a password directly
./crackulator -p "your_password_here"
```

### Docker Usage

```bash
# Run interactively
docker run -it crackulator

# Run with a password argument
docker run -it crackulator -p "your_password_here"
```

### Common Password Checking

Crackulator can check if your password appears in common password lists:

- **Local file checking**: Provide a path to a text file containing passwords (one per line)
- **Online checking**: Provide a URL to an online password list

### Hash Algorithm Selection

Crackulator supports multiple hashing algorithms:

- **Fast hashes**: MD5, SHA-1, SHA-256 (quicker to crack)
- **Slow hashes**: bcrypt (more resistant to cracking attempts)

The hash algorithm you select affects the estimated cracking time.

### System Selection

Choose from three system types to simulate password cracking speeds:

- **Slow PC**: Basic computing capacity (1-10 million hashes/sec)
- **Normal PC**: Average performance (100-500 million hashes/sec)
- **High-end GPU**: Advanced computing power (1-10+ billion hashes/sec)

### Benchmarking

Crackulator can benchmark your system's actual hashing performance to provide more accurate cracking time estimates, or use the predefined speeds based on your system selection.

### Cracking Time Estimation

The tool calculates:
- Character set size based on password composition
- Total possible combinations
- Estimated time to crack the password
- A human-readable assessment of the password's security
