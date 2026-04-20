// Custom shell - reimplements commands without spawning child processes
// Source: Evasion Engineering (Chow & LaSalvia) - Chapter 2, Listing 2-7
// https://nostarch.com/evasion-engineering

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// ls - list directory entries using direct syscall
func cmdLs(args []string) {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer syscall.Close(fd)

	entries, err := os.ReadDir(path)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	for _, entry := range entries {
		fmt.Println(entry.Name())
	}
}

// cat - read and print file using direct syscall
func cmdCat(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: cat <file>")
		return
	}

	fd, err := syscall.Open(args[0], syscall.O_RDONLY, 0)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	defer syscall.Close(fd)

	buf := make([]byte, 4096)
	for {
		n, err := syscall.Read(fd, buf)
		if n > 0 {
			os.Stdout.Write(buf[:n])
		}
		if err != nil {
			if err != io.EOF {
				fmt.Printf("\nError: %v\n", err)
			}
			break
		}
	}
}

// mv - rename file using direct syscall
func cmdMv(args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: mv <source> <dest>")
		return
	}

	err := syscall.Rename(args[0], args[1])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("Moved %s -> %s\n", args[0], args[1])
}

func main() {
	fmt.Println("[Custom Shell] No child processes spawned")
	fmt.Println("[Custom Shell] Commands: ls, cat, mv, exit")
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("$ ")
		if !scanner.Scan() {
			break
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]
		args := parts[1:]

		switch cmd {
		case "ls":
			cmdLs(args)
		case "cat":
			cmdCat(args)
		case "mv":
			cmdMv(args)
		case "exit":
			fmt.Println("Exiting...")
			return
		default:
			fmt.Printf("Command not found: %s\n", cmd)
		}
	}
}
