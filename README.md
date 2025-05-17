# 🔐 GKrypt

![Release](https://img.shields.io/github/v/release/gkavara/GKrypt?style=flat-square)
![License](https://img.shields.io/github/license/gkavara/GKrypt?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.7+-blue?style=flat-square)

**GKrypt** is a lightweight, secure file encryption tool with a graphical interface (Tkinter) built in Python.  
It uses state-of-the-art **AES-256-GCM** encryption and **PBKDF2 key derivation** for strong password-based file protection.

![GKrypt Logo](icons/gkrypt.ico)

## ✅ Features

- AES-256-GCM encryption (confidentiality + integrity)
- Password-based encryption with PBKDF2 + SHA-256
- Optional deletion of original files after encryption/decryption
- Friendly and clean GUI with English and Greek language support
- Logs all operations in daily files
- Supports drag & drop (via `tkinterdnd2`)
- Safe error handling with clear messages

  ---

## 📦 Download

👉 [⬇️ GKrypt_Setup.exe (Installer for Windows)](https://github.com/gkavara/GKrypt/releases/download/v1.0/GKrypt_Setup.exe)

No Python required – just run the installer and start encrypting your files securely.

---

## 📷 Screenshot

Here is what the GKrypt interface looks like:

<img src="https://raw.githubusercontent.com/gkavara/GKrypt/main/assets/gkrypt.png" alt="GKrypt GUI" width="500"/>

## 🧪 Cryptographic Design

- **Algorithm**: AES-256 in GCM mode (12-byte IV, 16-byte tag)
- **Key derivation**: PBKDF2 with SHA-256, 150,000 iterations, 16-byte salt
- **Metadata header**: Magic = `b'GK1'`, version = `0x01`
- **No password stored or cached**

## 🖥️ Requirements

```bash
pip install -r requirements.txt
```

## 🚀 How to Run

```bash
python src/gkrypt_gui.py
```

Or create a `.exe` using:

```bash
pyinstaller --noconfirm --onefile --noconsole --icon=icons/gkrypt.ico src/gkrypt_gui.py
```

## 📁 File Structure

```
├── src/                # Python code
├── icons/              # Icon files
├── logs/               # Auto-generated log files
├── README.md
├── LICENSE
├── requirements.txt
└── .gitignore
```

## 🛑 Security Warning

- Do not forget your password — there is no recovery.
- Always keep backup copies of your files before deleting the originals.

## 📜 License

This project is licensed under the [MIT License](LICENSE).

Created by **GK**, 2025.
