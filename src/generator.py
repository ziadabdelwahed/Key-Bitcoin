import secrets
import hashlib
from typing import List
from .crypto import BIP39_WORDS

COMMON_BRAINWALLETS = [
    "password", "12345678", "qwerty123", "letmein", "monkey123",
    "dragonball", "starwars", "naruto", "bitcoin", "ethereum",
    "satoshi", "vitalik", "correct horse battery staple",
    "to be or not to be", "purple monkey dishwasher",
    "hello world", "admin123", "rootroot", "testtest",
    "changeme", "secret123", "masterkey", "passw0rd",
    "iloveyou", "bitcoin1", "ethereum1",
    "metamask", "trustwallet", "blockchain", "crypto",
    "satoshi nakamoto", "vitalik buterin", "cz binance"
]

COMMON_FIRST_WORDS = [
    "abandon", "ability", "apple", "banana", "cat", "dog",
    "sun", "moon", "star", "love", "hope", "life", "gold",
    "blue", "red", "green", "king", "queen", "rock", "fire",
    "water", "earth", "wind", "bird", "fish", "tree", "rose"
]

def random_phrase(count: int = 12) -> str:
    wordlist = BIP39_WORDS if BIP39_WORDS else load_bip39_wordlist()
    indices = [secrets.randbelow(2048) for _ in range(count)]
    return ' '.join(wordlist[i] for i in indices)

def brainwallet_phrase(seed_phrase: str) -> str:
    wordlist = BIP39_WORDS if BIP39_WORDS else load_bip39_wordlist()
    h = hashlib.sha256(seed_phrase.encode()).digest()
    indices = [((h[i] << 8) | h[(i+1) % len(h)]) % 2048 for i in range(12)]
    return ' '.join(wordlist[i] for i in indices)

def sequential_phrase() -> str:
    wordlist = BIP39_WORDS if BIP39_WORDS else load_bip39_wordlist()
    start = secrets.randbelow(2048 - 12)
    return ' '.join(wordlist[start:start+12])

def repeated_word_phrase() -> str:
    wordlist = BIP39_WORDS if BIP39_WORDS else load_bip39_wordlist()
    word = wordlist[secrets.randbelow(2048)]
    return ' '.join([word] * 12)

def prefix_phrase(prefix: str) -> str:
    wordlist = BIP39_WORDS if BIP39_WORDS else load_bip39_wordlist()
    if prefix not in wordlist:
        return ""
    return prefix + ' ' + ' '.join(
        wordlist[secrets.randbelow(2048)] for _ in range(11)
    )

def typo_variant(phrase: str) -> str:
    wordlist = BIP39_WORDS if BIP39_WORDS else load_bip39_wordlist()
    words = phrase.split()
    if len(words) != 12:
        return phrase
    pos = secrets.randbelow(12)
    original = words[pos]
    variants = [w for w in wordlist if w[:3] == original[:3] and w != original]
    if variants:
        words[pos] = secrets.choice(variants)
    return ' '.join(words)

def generate_batch(count: int) -> List[str]:
    wordlist = BIP39_WORDS if BIP39_WORDS else load_bip39_wordlist()
    phrases = []
    
    for _ in range(int(count * 0.40)):
        phrases.append(random_phrase(12))
    for _ in range(int(count * 0.15)):
        phrases.append(brainwallet_phrase(secrets.choice(COMMON_BRAINWALLETS)))
    for _ in range(int(count * 0.10)):
        phrases.append(sequential_phrase())
    for _ in range(int(count * 0.10)):
        phrases.append(prefix_phrase(secrets.choice(COMMON_FIRST_WORDS)))
    for _ in range(int(count * 0.10)):
        phrases.append(repeated_word_phrase())
    for _ in range(int(count * 0.10)):
        phrases.append(typo_variant(random_phrase(12)))
    for _ in range(int(count * 0.05)):
        phrases.append(random_phrase(24))
    
    return phrases
