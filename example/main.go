package main

import (
	"encoding/hex"
	"fmt"

	mydes "../DES"
)

var version = "frankonly's DES v0.1"

// demo

func desEncrypt(c *mydes.Cipher, plaintext string) string {
	plainBytes := []byte(plaintext)
	plainBytes = append(plainBytes, make([]byte, 8-len(plainBytes)%8)...)

	ciphertext := ""
	for i := 0; i < len(plainBytes)/8; i++ {
		cipherByte := c.Encrypt(plainBytes[i*8 : i*8+8])
		ciphertext += hex.EncodeToString(cipherByte)
	}
	return "ciphertext:" + ciphertext
}
func desDecrypt(c *mydes.Cipher, ciphertext string) string {
	cipherBytes, err := hex.DecodeString(ciphertext)
	if err != nil {
		return "invalid ciphertext, we need hex ciphertext"
	}
	plaintext := ""
	for i := 0; i < len(cipherBytes)/8; i++ {
		plainByte := c.Decrypt(cipherBytes[i*8 : i*8+8])
		plaintext += string(plainByte)
	}
	return "plaintext:" + plaintext
}

func main() {
	fmt.Printf("%s\n\n", version)
	var option byte
	run := true
	fmt.Print("please input key: ")
	c := mydes.NewCipher([]byte(readText()))
	fmt.Println("cipher has been initialized")
	for run {
		fmt.Println("\nOptions:\n(1)Encrypt, (2)Decrypt, (3)Change Key, (4)Quit")
		_, _ = fmt.Scan(&option)
		switch option {
		default:
			fmt.Println("invalid input")
		case 1:
			fmt.Println("please input plaintext")
			fmt.Println(desEncrypt(c, readText()))
		case 2:
			fmt.Println("please input ciphertext")
			fmt.Println(desDecrypt(c, readText()))
		case 3:
			fmt.Println("please input key")
			c = mydes.NewCipher([]byte(readText()))
		case 4:
			run = false
		}
	}
}

func readText() (text string) {
	_, _ = fmt.Scan(&text)
	return
}
