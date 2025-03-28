# End-to-End Encrypted Chat Web Application

## Description
A secure chat web application implementing end-to-end encryption (E2EE) using ECDH key exchange, AES-GCM message encryption, and robust authentication mechanisms. Complies with NIST guidelines for digital identity and includes features such as multi-factor 
authentication (MFA), password strength validation, and protection against common security vulnerabilities.

## Architecture
### Backend
- **Language:** Python 3
- **Framework:** Flask

### Frontend
- **Technologies:** HTML, CSS, JavaScript

### Database
- **System:** MySQL

### Web Server
- **Server:** Nginx

### Container
- **Platform:** Docker

## Objectives

1. Transform a basic chat web application into a secure E2EE chat app.
2. Comply with NIST Special Publication 800-63B "Digital Identity Guidelines – Authentication and Lifecycle Management".
3. Implement a secure Multi-Factor Authentication (MFA) mechanism using passwords and OTP (or FIDO2).
4. Encrypt communications between users to ensure server-side confidentiality (E2E encryption).
5. Protect communications in transit by configuring a modern TLS deployment.
6. Package the application as a Docker image for easy deployment.

## Implementation

### 2.1 Authentication

#### 2.1.1 Registration
- The system checks the password strength score using Zxcvbn. If the score is less than 3, an alert displays: "Your password is too weak. Please choose a stronger password."
- The system checks if the password has been compromised using the Pwned Passwords API. If it has, an alert displays: "This password has been pwned. Please choose a different password."
- ReCaptcha verification is performed; if it fails, the user is prompted to register again.
- A QR code for connecting to Google Authenticator and a Recovery Key are displayed. Users must enter their OTP code to complete registration, and account info is stored in the database.

**Key Points:**
1. Database stores UserID, OTP key, Recovery key, and password for each account.
2. All OTP keys, recovery keys, and passwords are hashed and salted for enhanced security.
3. Password strength categories include "Very strong", "Strong", "Medium", "Weak", and "Very weak".
4. Public keys are generated and stored on the server, while private keys are stored locally on the user's device.

#### 2.1.2 Rate-limiting Mechanisms and Image-based CAPTCHAs
- reCAPTCHA v2 API is integrated into HTML pages. Flask_limiter monitors login attempts, redirecting users after three failed attempts.

#### 2.1.3 Password Pwned Check
- The Pwned Passwords API is used to verify if passwords have been compromised.

#### 2.1.4 Strong Password Checking
- Password strength is validated using zxcvbn.js.

#### 2.1.5 OTP
- The pyotp library is utilized for login and registration, along with pyqrcode to generate QR codes for OTP.

#### 2.1.6 Password Hashing
- Passwords are hashed and salted using bcrypt.

#### 2.1.7 Recovery Key
- A recovery key is provided during registration for modifying the OTP authenticator.

#### 2.1.8 Session Binding
- The backend ensures session integrity, terminating sessions with invalid checks.

### 2.2 E2EE Chat

#### 2.2.1 Select Contact
- Upon selecting a contact, the opponent's public key is retrieved to generate a shared key.
  ![image](https://github.com/user-attachments/assets/4488ccdb-5ed6-46bc-91c1-88bf4ff06516)


#### 2.2.2 Send Message
- ECDH key exchange is performed, followed by AES-GCM message encryption.
- Keys are stored in HTML5 Local Storage for persistence.
  ![image](https://github.com/user-attachments/assets/49939386-3298-4c85-bc68-c0d87e7e9f99)


#### 2.2.3 Receive Message
- Messages are decrypted using the AES key and MAC key, with integrity checks performed.
  ![image](https://github.com/user-attachments/assets/dac50dd7-01d8-4172-90d2-03f3c44440ee)


#### 2.2.4 Message Encoding
- Messages are encoded in UTF-8 and formatted in JSON.

#### 2.2.5 Refresh Key Mechanism
- A refresh button allows users to generate new keys and securely communicate.

#### 2.2.6 Message History
- Message history persists across sessions, with an option to erase chats.
  ![image](https://github.com/user-attachments/assets/016284ee-25ca-4ad0-8d36-1c3b31057087)


#### 2.2.7 Crypto Operations Logging
- All crypto operations are logged to the console for transparency.

#### 2.2.8 Security Measures
- CSRF, XSS, and SQL injection protections are implemented.

### 2.3 TLS

#### 2.3.1 Docker Configuration
- Necessary configurations for TLS are set in the nginx.conf and docker-compose.yaml files.

#### 2.3.2 Creating Certificates with OpenSSL
- A self-signed certificate is generated using OpenSSL commands.

#### 2.3.3 Implementation Result
- The final transport layer security setup meets all project requirements.

## Requirements

### Authentication

- Comply with NIST guidelines:
  - Use user-chosen memorized secrets (passwords) and Single-Factor OTP devices (e.g., Google Authenticator) or cryptographic devices (e.g., Yubikey).
  - Implement recovery keys (Look-Up Secrets).
  - All memorized secrets must be salted and hashed using a suitable one-way key derivation function.
  - Implement rate-limiting mechanisms and image-based CAPTCHAs.
  - Enable new account registration and allow binding of authenticators during the process.
  - Implement session binding requirements.

### End-to-End Encryption (E2EE)

- Use ECDH key exchange protocol to establish a shared secret.
- Derive AES-GCM encryption keys and MAC keys from the shared secret using HKDF-SHA256.
- Encrypt chat messages with AES in GCM mode using unique IVs.
- Store key material in HTML5 Local Storage for persistence.
- Implement a mechanism to refresh symmetric keys and manage key exchanges effectively.

### TLS Configuration

- Use Mozilla’s "modern" TLS configuration for nginx:
  - TLS version 1.3 only.
  - x25519 Elliptic Curve Group only.
  - TLS_CHACHA20_POLY1305_SHA256 cipher suite only.
  - Implement HSTS for one week.
  - Issue self-signed certificates with specified requirements.


## Deployment Instructions

1. Deploy the Docker container using:
   ```bash
   $ sudo docker-compose up -d
2. Access the chat application at:
      ```bash
   http://group-0.comp3334.xavier2dc.fr:8080
      
3. Open a private window in your browser to log in as different users:
Alice (password: password123)
Bob (password: password456)

4. Start chatting by selecting contacts and sending messages.

## License
This project is licensed under the MIT License. See the LICENSE file for more details.
