# 🛡️ StegoVault — Secure Image Communication Suite

**StegoVault** is an advanced web-based application built with Django that integrates cryptography, steganography, watermarking, and tamper detection. Designed for secure communication and digital forensic applications, StegoVault enables users to hide encrypted messages within images while verifying their integrity.

## 🚀 Features

- 🔐 **Cryptography**: AES + RSA hybrid encryption with secure message handling.
- 🖼️ **Steganography**: Embed encrypted messages into images using LSB techniques.
- 💧 **Watermarking (BlendMark Algorithm)**: 
  - Supports text and logo watermarks.
  - Allows custom placement (corners).
  - Encrypts and stores keys securely.
- 🧪 **Tamper Detection**: Verifies image authenticity using SHA-256 hashing at each phase (original, watermarked, steganographed).
- 🔔 **Real-Time Notifications**: Displays success and error messages via Django Channels dropdowns.
- 👤 **User Management**: Full authentication, profile updates, picture upload, password/email change.
- 📩 **Support Page**: Contact form for guests and users to reach developers.

## 🛠️ Technologies Used

- **Backend**: Python 3, Django 5.1.5, PostgreSQL
- **Frontend**: Bootstrap 4, HTML5, CSS3, JavaScript
- **Security & Processing**:
  - OpenCV (Image manipulation)
  - Cryptography (AES/RSA)
  - hashlib (SHA-256)

## 🧪 Security Highlights

- Secure password storage via Django's auth system
- AES-encrypted content with RSA-encrypted keys
- Hash-based tamper detection
- Key-based watermarking — prevents unauthorized access

## 👤 Author

**Developer:** [Jayaraj J Pillai]  
**Project:** Stego_Vault — Encrypted Image Vault with Steganography & Tamper Detection  
**Role:** Full-stack Security Developer

> 🔒 *Protecting secrets one pixel at a time.*
