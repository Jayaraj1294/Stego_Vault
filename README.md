# 🛡️ StegoVault — Secure Image Communication Suite

**StegoVault** is a powerful web application designed to protect, hide, and verify sensitive information within images. Built with Django and packed with security-first features, it brings together encryption, steganography, watermarking, and tamper detection — all in one intuitive platform.

Whether you're a student, researcher, or security professional, StegoVault lets you securely embed encrypted data in images, verify file authenticity, and prevent unauthorized access — all through a clean, responsive interface.

---

## 🚀 What Can You Do with StegoVault?

- 🔐 **Encrypt messages** using AES and RSA before hiding them inside images.
- 🖼️ **Hide (and later extract) messages** using LSB-based image steganography.
- 💧 **Watermark your images** with either a logo or text using the custom BlendMark algorithm.
- 🔏 **Encrypt watermarks** with AES, making them accessible only with the right key.
- 🧪 **Detect tampering** using SHA-256 hashes at every step (original → watermarked → steganographed).
- 🔔 **Get real-time notifications** through dropdown alerts powered by Django messages.
- 👤 **Manage your account**, update your profile or password, and upload a profile picture.
- 📩 **Reach out via support**, whether logged in or not — your queries go straight to the developer.

---

## 🛠️ Technologies Used

- **Backend**: Python 3, Django 5.1.5, PostgreSQL
- **Frontend**: Bootstrap 4, HTML5, CSS3, JavaScript
- **Security & Image Processing**:
  - `cryptography` library (AES & RSA)
  - `hashlib` for SHA-256 hashing
  - `OpenCV` for steganography and watermark embedding
  - `Django Channels` for real-time updates

---

## 🔐 Security Highlights

- Passwords are securely hashed using Django's built-in auth system.
- Messages are encrypted with AES keys, which are themselves encrypted using RSA.
- Watermarked and steganographed images are validated with tamper detection via SHA-256.
- Watermark extraction is **key-locked** — unauthorized users can’t retrieve it.

---

## 👨‍💻 About the Developer

**👋 Hi, I'm Jayaraj J Pillai**, the developer of **StegoVault** — an encrypted image vault with steganography and tamper detection. This project is the result of my passion for cybersecurity, secure communications, and real-world applications of digital forensics.

- 🔧 Role: Full-Stack Security Developer
- 🧠 Focus: Privacy-focused app development using secure, verifiable methods

---

> 🔒 *Protecting secrets one pixel at a time.*
