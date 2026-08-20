Recursively encrypt and decrypt files or directories with a password

<img width="965" height="341" alt="image" src="https://github.com/user-attachments/assets/9ed75a92-ace2-4a15-9f12-cfb44bc6928a" />

## Usage
```bash
# Encrypt a file
./fencrypt encrypt <input> <output> [-p password]

# Decrypt a file
./fencrypt decrypt <input> <output> [-p password]

# Encrypt all files recursively
./fencrypt dir-encrypt <directory> [-p password]

# Decrypt all files recursively
./fencrypt dir-decrypt <directory> [-p password]
```
