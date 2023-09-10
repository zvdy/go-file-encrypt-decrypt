package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

func main() {
	// Prompt the user for the file path
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter file path: ")
	filePath, _ := reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	// Prompt the user for encryption or decryption mode
	fmt.Print("Enter mode (encrypt or decrypt): ")
	mode, _ := reader.ReadString('\n')
	mode = strings.TrimSpace(mode)

	if mode == "encrypt" {
		// Prompt the user for a password
		fmt.Print("Enter password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		// Encrypt the file using AES-256 encryption
		err := encryptAES(filePath, password)
		if err != nil {
			panic(err)
		}
		fmt.Println("File encrypted successfully")
	} else if mode == "decrypt" {
		// Prompt the user for a password
		fmt.Print("Enter password: ")
		password, _ := reader.ReadString('\n')
		password = strings.TrimSpace(password)

		// Decrypt the file using AES-256 encryption
		err := decryptAES(filePath, password)
		if err != nil {
			panic(err)
		}
		fmt.Println("File decrypted successfully")
	} else {
		fmt.Println("Invalid mode")
	}
}

func encryptAES(filePath string, password string) error {
	// Read the file contents
	plaintext, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Generate a random initialization vector
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return err
	}

	// Derive a key from the password using SHA-256
	key := sha256.Sum256([]byte(password))

	// Create the AES cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}

	// Encrypt the plaintext
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, plaintext)

	// Write the encrypted data to a new file
	encryptedFilePath := filePath + ".enc"
	encryptedFile, err := os.Create(encryptedFilePath)
	if err != nil {
		return err
	}
	defer encryptedFile.Close()

	// Write the initialization vector to the file
	_, err = encryptedFile.Write(iv)
	if err != nil {
		return err
	}

	// Write the encrypted data to the file
	_, err = encryptedFile.Write(plaintext)
	if err != nil {
		return err
	}

	return nil
}

func decryptAES(filePath string, password string) error {
	// Read the encrypted file contents
	encryptedData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}

	// Decode the initialization vector from the file
	iv := encryptedData[:aes.BlockSize]

	// Derive a key from the password using SHA-256
	key := sha256.Sum256([]byte(password))

	// Create the AES cipher
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}

	// Decrypt the ciphertext
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(encryptedData[aes.BlockSize:], encryptedData[aes.BlockSize:])

	// Write the decrypted data to a new file
	decryptedFilePath := strings.TrimSuffix(filePath, ".enc")
	decryptedFile, err := os.Create(decryptedFilePath)
	if err != nil {
		return err
	}
	defer decryptedFile.Close()

	_, err = decryptedFile.Write(encryptedData[aes.BlockSize:])
	if err != nil {
		return err
	}

	return nil
}
