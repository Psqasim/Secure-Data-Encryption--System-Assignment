# Secure Vault

![Secure Vault](https://img.shields.io/badge/Secure-Vault-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.7%2B-blue)

A secure data storage system built with Streamlit that allows users to encrypt, store, and retrieve sensitive information with passkey protection.

## 🔒 Features

- **In-memory Encryption**: All data is encrypted using Fernet symmetric encryption
- **Passkey Protection**: Access stored data only with the correct passkey
- **Security Measures**: Three-attempt lockout system to prevent brute force attacks
- **Clean Interface**: Simple and intuitive UI for storing and retrieving data
- **Session-based Storage**: Data persists only for the duration of the session

## 📋 Requirements

- Python 3.7+
- Streamlit
- Cryptography package

## 🚀 Installation

1. Clone this repository or download the code:
```bash
git clone https://github.com/yourusername/secure-vault.git
cd secure-vault
```

2. Install required packages:
```bash
pip install streamlit cryptography
```

3. Run the application:
```bash
streamlit run app.py
```

## 🔍 Usage

### Storing Data
1. Navigate to the "Store Data" page using the sidebar
2. Enter your sensitive data in the text area
3. Create a passkey to protect your data
4. Click "Encrypt & Store"

### Retrieving Data
1. Navigate to the "Retrieve Data" page using the sidebar
2. Enter the passkey you used to encrypt the data
3. Click "Decrypt" to view your data

### Security Notes
- The default admin password is "admin123" (consider changing this in production)
- After 3 failed passkey attempts, the system will lock and require admin authentication
- All data is stored in-memory and will be lost when the application is closed

## 🛠️ Technical Details

### Security Implementation

The application uses multiple layers of security:

- **Password Hashing**: SHA-256 for secure passkey storage
- **Encryption**: Fernet symmetric encryption (AES-128 in CBC mode with PKCS7 padding)
- **Key Derivation**: SHA-256 for deriving encryption keys from passkeys
- **Session Management**: Streamlit's session state to maintain user session

### Core Functions

- `hash_passkey()`: Creates SHA-256 hash of passkeys for secure storage
- `get_fernet_key()`: Derives encryption key from passkey
- `encrypt_data()`: Encrypts plaintext with Fernet cipher
- `decrypt_data()`: Decrypts ciphertext with the correct passkey

## ⚠️ Limitations

- Data is stored in memory and will be lost when the application is restarted
- No database integration in the current version
- Basic authentication system (consider enhancing for production use)

## 🌟 Future Improvements

- Add database integration for persistent storage
- Implement user accounts with proper authentication
- Add file encryption capabilities
- Enhance UI with dark mode and customization options
- Add password strength requirements

## 📄 License

© 2024 SecureVault. All rights reserved.

## 👨‍💻 Authors

Made with ❤️ by **psqasim**

---

*Note: This application is for educational purposes. For storing critical data, consider professional security solutions.*