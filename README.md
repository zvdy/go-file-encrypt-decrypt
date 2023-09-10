# GO AES File Encryptor/Decryptor
This is a command-line tool for encrypting and decrypting files using AES-256 encryption. The tool prompts the user for the file path, encryption or decryption mode, and password.

### Usage
```
go run main.go
```

### Encryption
To encrypt a file, run the tool in encrypt mode and provide the file path and password when prompted:
```
Enter file path: /path/to/file.txt
Enter mode (encrypt or decrypt): encrypt
Enter password: mypassword
```


The encrypted file will be written to a new file with the extension _.enc_ appended to the original file name.

### Decryption
To decrypt a file, run the tool in decrypt mode and provide the file path and password when prompted:
```
Enter file path: /path/to/file.enc
Enter mode (encrypt or decrypt): decrypt
Enter password: mypassword
```

The decrypted file will be written to a new file with the _.enc_ extension removed from the original file name.

### Note
There is a sample encrypted file secret.enc included in the project for you to try decrypting using the tool. Good luck!