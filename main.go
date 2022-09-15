package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("6801|-1|1|ac68a20d5b3e606a4ba3d1accdf33"))
	})

	log.Println("Serving in port :8080")
	http.ListenAndServe(":8080", mux)
	// text := "irda islakhu afa"
	// key := "abcdefghijklmnopqrstuvwxyzxxxsss"

	// fmt.Println("Value:", text)

	// s, err := Encrypt(text, key)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("Encrypted:", hex.EncodeToString([]byte(*s)))

	// s, err = Decrypt(*s, key)
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Println("Decrypt:", *s)
}

func Decrypt(text, key string) (*string, error) {
	textByte, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}

	textByte, err = hex.DecodeString(string(textByte))
	if err != nil {
		return nil, err
	}

	text = string(textByte)

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	ahead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := ahead.NonceSize()
	if len(text) < nonceSize {
		return nil, errors.New("text is lower than nonce size")
	}

	nonce, encText := text[:nonceSize], text[nonceSize:]
	b, err := ahead.Open(nil, []byte(nonce), []byte(encText), nil)
	if err != nil {
		return nil, err
	}

	return func(s string) *string { return &s }(string(b)), nil
}

func Encrypt(text, key string) (*string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	ahead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, ahead.NonceSize())
	// if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
	// 	return nil, err
	// }
	res := ahead.Seal(nonce, nonce, []byte(text), nil)
	return func(s string) *string { return &s }(base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString(res)))), nil
}
