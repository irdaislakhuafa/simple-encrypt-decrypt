package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	key := base64.StdEncoding.EncodeToString([]byte("this is key string"))

	scanner := bufio.NewScanner(os.Stdin)

	mode := flag.String("mode", "encrypt", "Put mode here, available mode (encrypt/decrypt)")
	flag.Parse()

	fmt.Printf("Input Text: ")
	scanner.Scan()
	inputText := scanner.Text()

	switch *mode {
	case "encrypt":
		encText, err := EncryptAES256GCM([]byte(inputText), []byte(key))
		if err != nil {
			fmt.Println("Error: Cannot encrypt text => " + err.Error())
			os.Exit(1)
		}

		fmt.Println("Encrypted:", string(encText))

	case "decrypt":
		decText, err := DecryptAES256GCM([]byte(inputText), []byte(key))
		if err != nil {
			fmt.Println("Error: Cannot decrypt text => " + err.Error())
			os.Exit(1)
		}

		fmt.Println("Decrypted:", string(decText))
	default:
		fmt.Println("Error: Invalid flags!")
	}
}

func EncryptAES256GCM(text, key []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	s := string(gcm.Seal(nonce, nonce, []byte(text), nil))
	s = hex.EncodeToString([]byte(s))
	s = base64.StdEncoding.EncodeToString([]byte(s))

	return []byte(s), nil
}

func DecryptAES256GCM(text, key []byte) ([]byte, error) {
	text, err := base64.StdEncoding.DecodeString(string(text))
	if err != nil {
		return nil, err
	}

	text, err = hex.DecodeString(string(text))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	nonce, encText := text[:nonceSize], text[nonceSize:]
	res, err := gcm.Open(nil, nonce, encText, nil)
	if err != nil {
		return nil, err
	}

	return res, nil
}
