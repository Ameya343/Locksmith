"""
Locksmith — Password Strength Checker & Encryption
=======================================================
Features:
  • Password strength analysis with entropy estimation
  • Random secure password generator
  • AES-256-GCM encryption with random salt + IV (reversible)

Requirements:
    pip install cryptography

Usage:
    python locksmith.py
"""

import os
import re
import math
import secrets
import string
import base64
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ─────────────────────────────────────────────
# ANSI colours (graceful fallback on Windows)
# ─────────────────────────────────────────────
try:
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(
        ctypes.windll.kernel32.GetStdHandle(-11), 7
    )
except Exception:
    pass

RESET   = "\033[0m"
BOLD    = "\033[1m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
DIM     = "\033[2m"


def clr(text: str, c: str) -> str:
    return f"{c}{text}{RESET}"


def header(title: str) -> None:
    width = 54
    print()
    print(clr("┌" + "─" * width + "┐", CYAN))
    print(clr("│", CYAN) + BOLD + f"  {title}".ljust(width) + RESET + clr("│", CYAN))
    print(clr("└" + "─" * width + "┘", CYAN))


def divider() -> None:
    print(clr("─" * 56, DIM))


def pause() -> None:
    input(clr("\n  Press Enter to return to menu…", DIM))


# ══════════════════════════════════════════════
# CORE LOGIC
# ══════════════════════════════════════════════

# ── Strength checker ──────────────────────────

def check_strength(password: str) -> dict:
    criteria = {
        "8+ characters":     len(password) >= 8,
        "16+ characters":    len(password) >= 16,
        "Uppercase letter":  bool(re.search(r"[A-Z]", password)),
        "Lowercase letter":  bool(re.search(r"[a-z]", password)),
        "Number":            bool(re.search(r"[0-9]", password)),
        "Special character": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    pool = (
        (26 if criteria["Lowercase letter"]  else 0) +
        (26 if criteria["Uppercase letter"]  else 0) +
        (10 if criteria["Number"]            else 0) +
        (32 if criteria["Special character"] else 0)
    ) or 1
    entropy = round(len(password) * math.log2(pool), 1)
    score   = sum(criteria.values())

    levels = [
        (1, "Very weak",   RED),
        (2, "Weak",        RED),
        (3, "Fair",        YELLOW),
        (4, "Strong",      GREEN),
        (5, "Very strong", GREEN),
        (6, "Excellent",   CYAN),
    ]
    label, col = "Very weak", RED
    for min_s, lbl, c in levels:
        if score >= min_s:
            label, col = lbl, c

    return {"criteria": criteria, "score": score,
            "label": label, "color": col, "entropy_bits": entropy}


# ── Password generator ────────────────────────

def generate_password(length=20, upper=True, lower=True, digits=True, symbols=True) -> str:
    pool, guaranteed = "", []
    if upper:
        pool += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if lower:
        pool += string.ascii_lowercase
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if digits:
        pool += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if symbols:
        syms = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        pool += syms
        guaranteed.append(secrets.choice(syms))
    pool = pool or string.ascii_lowercase
    rest = [secrets.choice(pool) for _ in range(max(length - len(guaranteed), 0))]
    chars = guaranteed + rest
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)



# ── AES-256-GCM encryption / decryption ───────

def _derive_key(secret: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=260_000)
    return kdf.derive(secret.encode())


def encrypt_password(password: str, secret_key: str) -> str:
    """
    Reversible AES-256-GCM encryption.
    Fresh random salt + IV every call → different ciphertext each time.
    Format:  aes:<b64_salt>:<b64_iv>:<b64_ciphertext>
    """
    salt, iv = os.urandom(16), os.urandom(12)
    key      = _derive_key(secret_key, salt)
    cipher   = AESGCM(key).encrypt(iv, password.encode(), None)
    b64      = lambda b: base64.urlsafe_b64encode(b).decode()
    return f"aes:{b64(salt)}:{b64(iv)}:{b64(cipher)}"


def decrypt_password(token: str, secret_key: str) -> str:
    """Decrypt a token produced by encrypt_password(). Raises ValueError on failure."""
    parts = token.split(":")
    if len(parts) != 4 or parts[0] != "aes":
        raise ValueError("Not a valid AES-GCM token (expected aes:<salt>:<iv>:<cipher>).")
    try:
        b64d         = lambda s: base64.urlsafe_b64decode(s + "==")
        salt, iv, cipher = b64d(parts[1]), b64d(parts[2]), b64d(parts[3])
    except Exception:
        raise ValueError("Corrupted token — could not decode base64 components.")
    try:
        return AESGCM(_derive_key(secret_key, salt)).decrypt(iv, cipher, None).decode()
    except Exception:
        raise ValueError("Decryption failed — wrong secret key or tampered data.")



# ══════════════════════════════════════════════
# MENU ACTIONS
# ══════════════════════════════════════════════

def action_check_strength() -> None:
    header("🔍  Password Strength Checker")
    pw = getpass.getpass(clr("  Enter password (hidden): ", CYAN))
    if not pw:
        print(clr("  No password entered.", RED))
        return

    r      = check_strength(pw)
    filled = round(r["score"] / 6 * 22)
    bar    = "█" * filled + "░" * (22 - filled)

    print()
    print(f"  Strength : {clr(bar, r['color'])}  {clr(BOLD + r['label'], r['color'])}")
    print(f"  Entropy  : {clr(str(r['entropy_bits']) + ' bits', CYAN)}")
    print()
    for criterion, passed in r["criteria"].items():
        tick  = clr("✔", GREEN) if passed else clr("✘", RED)
        label = clr(criterion, GREEN if passed else DIM)
        print(f"  {tick}  {label}")


def action_generate() -> None:
    header("⚙️   Secure Password Generator")
    try:
        length = int(input(clr("  Length (default 20): ", CYAN)).strip() or "20")
    except ValueError:
        length = 20

    def ask(prompt: str) -> bool:
        return input(clr(f"  Include {prompt}? [Y/n]: ", CYAN)).strip().lower() != "n"

    pw = generate_password(length, ask("uppercase (A-Z)"), ask("lowercase (a-z)"), ask("digits (0-9)"), ask("symbols (!@#…)"))
    print()
    print(f"  {clr('Generated :', DIM)} {clr(BOLD + pw, GREEN)}")
    divider()
    # show strength of generated password too
    r      = check_strength(pw)
    filled = round(r["score"] / 6 * 22)
    bar    = "█" * filled + "░" * (22 - filled)
    print(f"  Strength  : {clr(bar, r['color'])}  {clr(r['label'], r['color'])}")
    print(f"  Entropy   : {clr(str(r['entropy_bits']) + ' bits', CYAN)}")



def action_encrypt() -> None:
    header("🔐  Encrypt Password  (AES-256-GCM)")
    print(f"  {clr('Note:', YELLOW)} Random salt + IV each time → same password gives a different token.\n")

    pw  = getpass.getpass(clr("  Password to encrypt (hidden): ", CYAN))
    key = getpass.getpass(clr("  Secret key         (hidden): ", CYAN))
    if not pw or not key:
        print(clr("  Both password and secret key are required.", RED))
        return

    token = encrypt_password(pw, key)
    p     = token.split(":")
    print()
    print(f"  {clr('Salt   (b64):', DIM)} {clr(p[1], MAGENTA)}")
    print(f"  {clr('IV     (b64):', DIM)} {clr(p[2], MAGENTA)}")
    print(f"  {clr('Cipher (b64):', DIM)} {clr(p[3][:48] + '…', GREEN)}")
    print()
    print(f"  {clr('Full encrypted token:', DIM)}")
    print(f"  {clr(token, CYAN)}")
    print()
    print(clr("  ⚠  Keep your secret key safe — it is NOT stored in the token.", YELLOW))



def action_decrypt() -> None:
    header("🔓  Decrypt Password  (AES-256-GCM)")
    print(f"  {clr('Note:', YELLOW)} Only tokens produced by the Encrypt option can be decrypted.\n")

    token = input(clr("  Paste encrypted token: ", CYAN)).strip()
    key   = getpass.getpass(clr("  Secret key (hidden): ", CYAN))
    if not token or not key:
        print(clr("  Both token and secret key are required.", RED))
        return

    try:
        plain = decrypt_password(token, key)
        print()
        print(f"  {clr('✔  Decrypted password:', GREEN)} {clr(BOLD + plain, GREEN)}")
    except ValueError as e:
        print()
        print(clr(f"  ✘  {e}", RED))


def action_exit() -> None:
    print(clr("\n  Goodbye! Stay secure. 🔒\n", GREEN))


# ══════════════════════════════════════════════
# SWITCH-CASE DISPATCHER
# ══════════════════════════════════════════════

MENU = {
    "1": ("Check password strength",          action_check_strength),
    "2": ("Generate a secure password",        action_generate),
    "3": ("Encrypt password  (AES-256-GCM)",  action_encrypt),
    "4": ("Decrypt password  (AES-256-GCM)",  action_decrypt),
    "0": ("Exit",                              action_exit),
}


def dispatch(choice: str) -> bool:
    """
    Switch-case dispatcher.
    Returns False when the user chooses to exit, True otherwise.
    """
    match choice:
        case "1":
            action_check_strength()
            return True
        case "2":
            action_generate()
            return True
        case "3":
            action_encrypt()
            return True
        case "4":
            action_decrypt()
            return True
        case "0":
            action_exit()
            return False
        case _:
            print(clr("\n  ✘  Invalid choice — enter a number from the menu.", RED))
            return True


# ══════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════

def print_banner() -> None:
    os.system("cls" if os.name == "nt" else "clear")
    print(clr(BOLD + """
  ╔══════════════════════════════════════════════════════════════════════════════╗
  ║                                                                              ║
  ║  ██╗      ██████╗  ██████╗██╗  ██╗ ███████╗███╗   ███╗██╗████████╗██╗  ██╗   ║
  ║  ██║     ██╔═══██╗██╔════╝██║ ██╔╝ ██╔════╝████╗ ████║██║   ██╔══╝██║  ██║   ║
  ║  ██║     ██║   ██║██║     █████╔╝  ███████╗██╔████╔██║██║   ██║   ███████║   ║
  ║  ██║     ██║   ██║██║     ██╔═██╗  ╚════██║██║╚██╔╝██║██║   ██║   ██╔══██║   ║
  ║  ███████╗╚██████╔╝╚██████╗██║  ██╗ ███████║██║ ╚═╝ ██║██║   ██║   ██║  ██║   ║
  ║  ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚══════╝╚═╝     ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝   ║
  ║                                                                              ║
  ║   Password Strength · Generate                                               ║
  ║   Encrypt  ·  Decrypt  ·  AES-256-GCM                                        ║
  ║                                                                              ║
  ╚══════════════════════════════════════════════════════════════════════════════╝""", CYAN) + RESET)


def print_menu() -> None:
    print()
    divider()
    print(clr("  MAIN MENU", DIM))
    divider()
    icons = {"1": "🔍", "2": "⚙️ ", "3": "🔐", "4": "🔓", "0": "🚪"}
    for key, (label, _) in MENU.items():
        print(f"  {clr('[' + key + ']', CYAN)}  {icons[key]}  {label}")
    divider()


def main() -> None:
    print_banner()
    while True:
        print_menu()
        choice = input(clr("\n  Enter your choice: ", CYAN)).strip()
        keep_running = dispatch(choice)
        if not keep_running:
            break
        pause()


if __name__ == "__main__":
    main()
