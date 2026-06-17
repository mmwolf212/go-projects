package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

func decodeCaesar(ciphertext string, shift int) string {
	shift = ((shift % 26) + 26) % 26
	var b strings.Builder
	for _, ch := range ciphertext {
		switch {
		case ch >= 'A' && ch <= 'Z':
			b.WriteRune('A' + (ch-'A'-rune(shift)+26)%26)
		case ch >= 'a' && ch <= 'z':
			b.WriteRune('a' + (ch-'a'-rune(shift)+26)%26)
		default:
			b.WriteRune(ch)
		}
	}
	return b.String()
}

func findFlag(ciphertext, prefix string)(shift int, decoded, flag string, found bool){
	re := regexp.MustCompile(`(?i)` + regexp.QuoteMeta(prefix) + `\{[^{}]*\}`)
	for s :=0; s < 26; s++ {
		d := decodeCaesar(ciphertext, s)
		if m := re.FindString(d); m != ""{
			return s, d, m, true 
		}
	}
	return 0, "", "", false
}


func searchAndReport(ciphertext, prefix string) bool {
	shift, decoded, flag, found := findFlag(ciphertext, prefix)
	if found {
		fmt.Printf("\n[+] Found at shift %d\n", shift)
		fmt.Printf("[+] Flag: %s\n", flag)
		fmt.Printf("[+] Full decode: %s\n", decoded)
	} else {
		fmt.Printf("\n[-] No shift produced %s{...}\n", prefix)
	}
	return found
}

func bruteForce (ciphertext string){
	for shift :=0; shift < 26; shift ++{
		fmt.Printf("Shift %2d: %s\n", shift, decodeCaesar(ciphertext, shift))
	}
}

func main(){
	reader := bufio.NewReader(os.Stdin)

	readLine := func(prompt string) string {
		fmt.Print(prompt)
		line, _ := reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}

	text := readLine("Enter ciphertext: ")

	fmt.Println("\nChoose a mode:")
	fmt.Println(" 1. Flag in Ciphertext")
	fmt.Println(" 2. Flag in NOT in Ciphertext")
	fmt.Println(" 3. Unsure. Try both.")
	mode := strings.TrimSpace(readLine("Mode: (1/2/3): "))

	switch mode {
	case "1":
		prefix := readLine ("Flag prefix: ")
		searchAndReport(text, prefix)
	case "2":
		fmt.Println()
		bruteForce(text)
	case "3":
		prefix := readLine("Flag prefix: ")
		if !searchAndReport(text, prefix){
			fmt.Println("\nDumping all Shifts:\n")
			bruteForce(text)
			
		}
	default:
		fmt.Println("Invalid mode")
	}
	
}