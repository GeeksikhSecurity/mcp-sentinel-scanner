package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"../utils"  // Path traversal pattern
)

const API_KEY = "sk-1234567890abcdef" // Hardcoded secret

func main() {
	// Command injection vulnerability
	userInput := os.Args[1]
	cmd := exec.Command("sh", "-c", "echo "+userInput)
	cmd.Run()

	// Path traversal
	filename := "../../../etc/passwd"
	filepath.Join("/safe", filename)

	// SQL injection pattern
	query := "SELECT * FROM users WHERE id = '" + userInput + "'"
	fmt.Println(query)
}

func TestFunction() {
	// This should be detected as test context
	MOCK_SECRET := "test-secret-123456789"
	fmt.Println(MOCK_SECRET)
}