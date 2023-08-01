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
	"strconv"
)

func main() {
	key := base64.StdEncoding.EncodeToString([]byte("this is key string"))

	scanner := bufio.NewScanner(os.Stdin)

	mode := flag.String("mode", "encrypt", "Put mode here, available mode (encrypt/decrypt)")
	inputText := flag.String("value", "", "Put value you want to by encrypted here")
	flag.Parse()

	if *inputText == "" {
		fmt.Printf("Input Text: ")
		scanner.Scan()
		*inputText = scanner.Text()
	}

	switch *mode {
	case "encrypt":
		encText, err := EncryptAES256GCM([]byte(*inputText), []byte(key))
		if err != nil {
			fmt.Println("Error: Cannot encrypt text => " + err.Error())
			os.Exit(1)
		}

		fmt.Println("Encrypted:", string(encText))

	case "decrypt":
		decText, err := DecryptAES256GCM([]byte(*inputText), []byte(key))
		if err != nil {
			fmt.Println("Error: Cannot decrypt text => " + err.Error())
			os.Exit(1)
		}

		fmt.Println("Decrypted:", string(decText))
	case "createKey":
		keySize, err := strconv.Atoi(*inputText)
		if err != nil {
			fmt.Println("Error: Cannot create key => " + err.Error())
			os.Exit(1)
		}

		listAllowedKeySize := []int{128, 192, 256}
		contains := func(value int, slices ...int) bool {
			for _, allowedKeySize := range listAllowedKeySize {
				if value == allowedKeySize {
					return true
				}
			}

			return false
		}

		if !contains(keySize, listAllowedKeySize...) {
			fmt.Printf("Error: Allowed key size is => %+v\n", listAllowedKeySize)
			os.Exit(1)
		}

		key := make([]byte, keySize)
		if _, err := rand.Read(key); err != nil {
			fmt.Println("Error: Cannot generate AES key => " + err.Error())
			os.Exit(1)
		}

		fmt.Println(base64.StdEncoding.EncodeToString(key))
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
