# 🔐 Locksmith

> A command-line password toolkit — check strength, generate secure passwords, and encrypt/decrypt using AES-256-GCM.

```
  ██╗      ██████╗  ██████╗██╗  ██╗ ███████╗███╗   ███╗██╗████████╗██╗  ██╗
  ██║     ██╔═══██╗██╔════╝██║ ██╔╝ ██╔════╝████╗ ████║██║   ██╔══╝██║  ██║   
  ██║     ██║   ██║██║     █████╔╝  ███████╗██╔████╔██║██║   ██║   ███████║
  ██║     ██║   ██║██║     ██╔═██╗  ╚════██║██║╚██╔╝██║██║   ██║   ██╔══██║
  ███████╗╚██████╔╝╚██████╗██║  ██╗ ███████║██║ ╚═╝ ██║██║   ██║   ██║  ██║
  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚══════╝╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
    
    Password Strength · Generate
       Encrypt  ·  Decrypt  ·  AES-256-GCM
    
```

---

## Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | 🔍 **Strength Checker** | Analyses your password in real-time with an entropy score and per-criterion breakdown |
| 2 | ⚙️ **Password Generator** | Generates cryptographically random passwords with configurable length and character sets |
| 3 | 🔐 **Encrypt** | Encrypts any password using AES-256-GCM with a secret key — a fresh random salt + IV every time |
| 4 | 🔓 **Decrypt** | Decrypts any token produced by the Encrypt option using the original secret key |

---

## Requirements

- Python 3.10 or higher *(required for `match/case` syntax)*
- [`cryptography`](https://pypi.org/project/cryptography/) library

---

## Installation

**1. Clone the repo**
```bash
git clone https://github.com/yourusername/locksmith.git
cd locksmith
```

**2. Install the dependency**
```bash
pip install cryptography
```

**3. Run**
```bash
python locksmith.py
```

---

## Usage

Launch the tool and pick an option from the menu:

```
──────────────────────────────────────────────────────
  MAIN MENU
──────────────────────────────────────────────────────
  [1]  🔍  Check password strength
  [2]  ⚙️   Generate a secure password
  [3]  🔐  Encrypt password  (AES-256-GCM)
  [4]  🔓  Decrypt password  (AES-256-GCM)
  [0]  🚪  Exit
──────────────────────────────────────────────────────
```

### Strength Checker

Enter any password and get an instant analysis:

```
  Strength : ████████████████████  Excellent
  Entropy  : 118.0 bits

  ✔  8+ characters
  ✔  16+ characters
  ✔  Uppercase letter
  ✔  Lowercase letter
  ✔  Number
  ✔  Special character
```

### Password Generator

Choose your preferred length and character sets. The generator uses Python's `secrets` module (cryptographically secure) and guarantees at least one character from each selected class.

### Encrypt

Enter the password you want to protect and a secret key. A random salt and IV are generated every call, so the same password always produces a different token:

```
  Salt   (b64): 3q2-abc123...
  IV     (b64): xyz789...
  Cipher (b64): Ug3fK9...

  Full encrypted token:
  aes:3q2-abc123...:xyz789...:Ug3fK9...

  ⚠  Keep your secret key safe — it is NOT stored in the token.
```

### Decrypt

Paste the `aes:...` token and enter the same secret key to recover the original password:

```
  ✔  Decrypted password: myOriginalPassword
```

---

## How it works

### AES-256-GCM Encryption

Each encryption call:
1. Generates a 16-byte random **salt** via `os.urandom`
2. Derives a 256-bit AES key from your secret using **PBKDF2-HMAC-SHA256** (260,000 iterations)
3. Generates a 12-byte random **IV**
4. Encrypts using **AES-256-GCM** (authenticated encryption — detects tampering)
5. Returns a self-contained token: `aes:<b64_salt>:<b64_iv>:<b64_ciphertext>`

The salt and IV are embedded in the token so decryption only needs the token + secret key.

### Password Strength Scoring

Passwords are scored across 6 criteria (8+ chars, 16+ chars, uppercase, lowercase, digits, symbols). Entropy is calculated as:

```
entropy = length × log₂(pool_size)
```

where `pool_size` is the number of distinct character types used.

---

## Token Format

```
aes : <base64url_salt> : <base64url_iv> : <base64url_ciphertext>
 │          │                  │                   │
 │     16 random bytes    12 random bytes    encrypted data
 │     for key derivation  for AES-GCM        + GCM auth tag
 │
 └── prefix to identify AES-GCM tokens
```

> ⚠️ **Important:** The secret key is never stored anywhere. If you lose it, the encrypted token cannot be recovered.

---

## Security Notes

- All random values use `os.urandom` (cryptographically secure)
- PBKDF2 key derivation uses 260,000 iterations to slow down brute-force attacks
- AES-GCM provides both confidentiality and authenticity (decryption will fail if the token is tampered with)
- Passwords are entered via `getpass` so they never appear on screen

---

## Project Structure

```
locksmith/
├── src/
|    ├── Locksmith.py # Main script — all logic in one file
|   
└── README.md
```

---

## License

[`MIT`](https://github.com/Ameya343/Locksmith/blob/main/LICENSE) — do whatever you like, just don't blame me if you forget your secret key.

---

## Author

### [Ameya343](https://github.com/Ameya343)

