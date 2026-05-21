import hashlib
import hmac
from typing import List, Optional

BIP39_WORDS = []  # Will be loaded from file

def load_bip39_wordlist(filepath: str = None) -> List[str]:
    global BIP39_WORDS
    if filepath and BIP39_WORDS:
        return BIP39_WORDS
    
    if filepath:
        with open(filepath, 'r') as f:
            BIP39_WORDS = [line.strip() for line in f if line.strip()]
    else:
        # Use embedded wordlist
        BIP39_WORDS = [
            "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
            # ... (الكود السابق كاملاً - اختصرته هنا للتوضيح)
            "zebra","zero","zone","zoo"
        ]
    return BIP39_WORDS

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048, 64)

def seed_to_master_key(seed: bytes) -> bytes:
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return h[:32]
