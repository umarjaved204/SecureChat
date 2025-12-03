# SecureChat – Assignment \#2 (CS-3002 Information Security, Fall 2025)

This repository contains the completed implementation for Assignment \#2.
This project is a console-based, PKI-enabled Secure Chat System in Python, demonstrating how cryptographic primitives combine to achieve **Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

**Author:** Umar Javed
**Roll No:** 22i-1050

## 🧩 Overview

This project implements a secure, multi-client chat server from scratch, without using any high-level TLS/SSL abstractions. The application-layer protocol was built to satisfy all requirements from the assignment specification.

The final implementation includes:

  * **PKI & Mutual Authentication:** A functional Root CA (`scripts/gen_ca.py`) and certificate generation script (`scripts/gen_cert.py`). The server and client use these certificates to verify each other's identity.
  * **Secure Registration & Login:** User credentials are secured in transit using a temporary Diffie-Hellman key exchange and AES encryption. Passwords are stored in a MariaDB (MySQL) database using a unique 16-byte salt and a SHA-256 hash.
  * **Secure Chat Session:** After login, a second Diffie-Hellman exchange creates a main session key for the chat.
  * **CIANR-Enabled Chat:** All chat messages are encrypted (Confidentiality), signed with the sender's private RSA key (Authenticity, Integrity), and protected from replay attacks (Integrity).
  * **Non-Repudiation:** Both client and server generate append-only transcripts and a final, signed `SessionReceipt` to create a verifiable record of the chat.

## 🏗️ Folder Structure

```
securechat-skeleton/
├─ app/
│  ├─ client.py            # Client workflow
│  ├─ server.py            # Server workflow
│  ├─ crypto/
│  │  ├─ aes.py             # AES-128-CBC + PKCS#7
│  │  ├─ dh.py              # Classic DH helpers + key derivation
│  │  ├─ pki.py             # X.509 validation (CA signature, validity, CN)
│  │  └─ sign.py            # RSA SHA-256 sign/verify (PKCS#1 v1.5)
│  ├─ common/
│  │  └─ utils.py           # Networking (send/receive) helpers
│  └─ storage/
│     ├─ db.py              # MySQL user store (salted SHA-256)
│     └─ transcript.py      # Append-only transcript + transcript hash
├─ scripts/
│  ├─ gen_ca.py            # Create Root CA
│  └─ gen_cert.py          # Issue client/server certs
├─ tests/
│  ├─ mitm_proxy.py        # Proxy for Tamper & Replay attacks
│  └─ verify_transcript.py # Offline transcript/receipt verifier
├─ tests/manual/NOTES.md   # Original manual testing checklist
├─ certs/                  # Generated certs/keys (gitignored)
├─ transcripts/            # Generated logs/receipts (gitignored)
├─ .env.example
├─ .gitignore
├─ requirements.txt
└─ schema_dump.sql         # SQL dump for GCR submission
```

## ⚙️ Setup & Execution Instructions

This project was built and tested on **Kali Linux** with a local **MariaDB** server.

### 1\. Initial Setup

  * **Fork and Clone:** Clone your private repository.

  * **Set up Python Environment:**

    ```bash
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    ```

  * **Start MariaDB (MySQL):**

    ```bash
    sudo systemctl start mariadb
    ```

  * **Configure Database:**

    1.  Log in as root: `sudo mysql -u root -p`
    2.  Create the user and database (use the password set in `app/storage/db.py`):
        ```sql
        CREATE DATABASE secure_chat;
        CREATE USER 'chat_app_user'@'localhost' IDENTIFIED BY '123Password';
        GRANT ALL PRIVILEGES ON secure_chat.* TO 'chat_app_user'@'localhost';
        FLUSH PRIVILEGES;
        EXIT;
        ```

    > **Note:** The credentials (`chat_app_user`, `123Password`, `secure_chat`) are hardcoded in `app/storage/db.py` as per our development.

  * **Create Database Tables:**

    ```bash
    python -m app.storage.db
    ```

    You should see: `Database initialized. 'users' table is ready.`

  * **Generate Certificates:**

    ```bash
    python scripts/gen_ca.py --name "FAST-NU Root CA"
    python scripts/gen_cert.py --cn server.local --out certs/server
    python scripts/gen_cert.py --cn client.local --out certs/client
    ```

### 2\. Running the Chat

  * **Start the Server:**

    ```bash
    # In Terminal 1 (with .venv active)
    python -m app.server
    ```

    Server will be listening on `localhost:12345`.

  * **Start the Client(s):**

    ```bash
    # In Terminal 2 (with .venv active)
    python -m app.client
    ```

    You can now **Register** a new user or **Login**.
    You can run `python -m app.client` in multiple terminals to have a group chat.

-----

## 🧪 Running the Security Tests

All test scripts are located in the `tests/` directory.

### Test 1: Wireshark

*(See TestReport-A02.docx for screenshots)*

1.  Run `sudo wireshark` and capture on the `lo` interface.
2.  Use display filter: `tcp.port == 12345`
3.  Run the client and log in.
4.  Right-click the stream and select **Follow \> TCP Stream**.
5.  **Result:** All sensitive data (payload, ct) is shown as encrypted Base64.

### Test 2: Invalid Certificate (BAD\_CERT)

1.  Generate a self-signed certificate:
    ```bash
    openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/bad_key.pem -out certs/bad_cert.pem -subj "/CN=Evil"
    ```
2.  Edit `app/client.py` to use `bad_cert.pem` and `bad_key.pem`.
3.  Run `app.server` and `app.client`.
4.  **Result:** The server prints `BAD_CERT: Invalid signature` and the client receives the error.

*(Remember to revert `app/client.py` after this test.)*

### Test 3 & 4: Tamper (SIG\_FAIL) & Replay (REPLAY)

These tests use the `mitm_proxy.py` script.

1.  **Start Server:** (Terminal 1) `python -m app.server`
2.  **Start Proxy:** (Terminal 2) `python tests/mitm_proxy.py`
3.  **Configure Client:** Edit `app/client.py` and change the connection port to `12346` (the proxy).
4.  **Run Client:** (Terminal 3) `python -m app.client`
5.  **Perform Attack:**
      * **Tamper:** Send one message. The proxy will flip a bit, and the server will print `SIGNATURE FAILED`.
      * **Replay:** Send "message one", then "message two". The proxy will replay "message one". The server will print `REPLAY DETECTED`.

*(Remember to change the client port back to `12345` after.)*

### Test 5: Non-Repudiation (Offline Verification)

1.  Run a normal chat session (client and server) and send a few messages before typing `quit`.

2.  This generates `.log` and `.json` files in the `transcripts/` folder.

3.  **Run Verifier (Success):**

    ```bash
    python tests/verify_transcript.py \
      --transcript transcripts/client_...log \
      --receipt transcripts/receipt_client_...json \
      --cert certs/client_cert.pem
    ```

    **Result:** `FINAL RESULT: SUCCESS!`

4.  **Run Verifier (Tamper):**

      * Edit a character in the `.log` file.
      * Re-run the command from step 3.
      * **Result:** `[FAIL] Hash Mismatch! Result: Transcript has been tampered with!`

-----

## 🧾 Deliverables

  * A ZIP of this GitHub repository.
  * `schema_dump.sql` (MySQL schema dump).
  * This updated README.md.
  * `i221050-Umar Javed-Report-A02.pdf`
  * `i221050-Umar Javed-TestReport-A02.pdf`
