# SecureCrypt-Secure-encrypted-text-encrypter
# 🔐 SecureCrypt

**SecureCrypt** is a modern GUI-based XOR encryption and decryption application built using Python and [ttkbootstrap](https://ttkbootstrap.readthedocs.io/). It provides a secure and interactive interface to perform basic text encryption with password protection using XOR combined with PBKDF2-HMAC-SHA256 hashing.

> ⚠️ For educational and basic security use only. Not recommended for production-grade encryption.
---
## 📌 Features
- 🔒 **Encrypt/Decrypt text** using XOR with password-based hashing
- 🧠 **PBKDF2-HMAC-SHA256** used for password verification
- 🎨 **Modern dark-mode UI** powered by `ttkbootstrap`
- 🔐 **3-password attempt limit** to prevent brute-force
- 📋 **Clipboard copy** for encrypted/decrypted text
- 🧾 About tab with version info and author details
- 🪟 Tabbed interface: Encrypt | Decrypt | About

---

## 🛠️ Installation
### 📦 Requirements
- Python 3.8+
- `ttkbootstrap` (GUI toolkit)
  
### 📥 Install dependencies
```bash
pip install ttkbootstrap

🚀 Usage
💡 Run the App
python encry.py
✨ Tabs


🔒 Encrypt
Input plaintext and password
Output will be a secure hexadecimal string
🔓 Decrypt
Paste encrypted hex and enter the correct password
Displays original plaintext
ℹ️ About
Information about the app, author, and license
🔧 How It Works
🔐 Encryption Process
Password is hashed using:
python
Copy
Edit
hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

The hash is prefixed to the plaintext (for password verification)
The combined string is XOR'd with the password
Output is hex-encoded for readability
🔓 Decryption Process
Input hex is decoded
XOR'd back using the password
Password hash is compared for verification
If correct, plaintext is revealed
3 wrong attempts = app exits

🧪 Example
Plaintext: hello world
Password: 1234
➡️ Output:
3d5b124a1c3f... (hexadecimal encrypted string)
Paste it in the decrypt tab with the same password to recover original message.

📁 Project Structure
encryt.py        # Main app
README.md             # Documentation
🔐 Security Notes
This tool demonstrates encryption concepts and UI design. It is not suitable for production or securing sensitive data.
If you need serious encryption, consider using:
AES (with PyCryptodome)
Fernet (from cryptography package)

👨‍💻 Author
Haseeb ur Rahman
Version: 1.0
