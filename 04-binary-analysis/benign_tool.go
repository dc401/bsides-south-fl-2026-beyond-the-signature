// Benign Go tool for comparison testing
// Purpose: Legitimate system utility to test false positive rate

package main

import (
	"fmt"
	"os"
	"os/user"
)

func main() {
	fmt.Println("System Information Tool v1.0")
	fmt.Println("===========================")

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		fmt.Println("Error getting user:", err)
		return
	}

	fmt.Printf("User: %s\n", currentUser.Username)
	fmt.Printf("Home: %s\n", currentUser.HomeDir)

	// Get hostname
	hostname, err := os.Hostname()
	if err == nil {
		fmt.Printf("Hostname: %s\n", hostname)
	}

	fmt.Println("\nSystem check complete.")
}
