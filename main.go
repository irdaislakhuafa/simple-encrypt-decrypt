package main

import "fmt"

func main() {
	var inputText string
	fmt.Printf("Input Text: ")
	if _, err := fmt.Scanln(&inputText); err != nil {
		panic(err)
	}
	fmt.Println("Encrypted:", inputText)
}
