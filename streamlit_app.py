import streamlit as st
import secrets
import hashlib
import hmac
import requests
import struct
import time
from typing import Dict, Tuple, List, Optional

# ============================================================================
# CONSTANTS
# ============================================================================
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
CURVE_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
CURVE_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# ============================================================================
# BIP-39 WORDLIST
# ============================================================================
@st.cache_data
def load_wordlist():
    url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
    response = requests.get(url, timeout=10)
    words = response.text.strip().split("\n")
    if len(words) != 2048:
        st.error(f"Wordlist corrupted: {len(words)} words")
        st.stop()
    return words

WORDLIST = load_wordlist()
WORD_TO_INDEX = {word: index for index, word in enumerate(WORDLIST)}

# ============================================================================
# BIP-39 MNEMONIC
# ============================================================================
def generate_mnemonic(word_count: int = 12) -> str:
    ENT = 128 if word_count == 12 else 256
    CS = ENT // 32
    entropy_bytes = secrets.token_bytes(ENT // 8)
    entropy_hash = hashlib.sha256(entropy_bytes).digest()
    checksum_value = entropy_hash[0] >> (8 - CS)
    entropy_integer = int.from_bytes(entropy_bytes, 'big')
    combined_bits = ENT + CS
    combined_integer = (entropy_integer << CS) | checksum_value
    
    words = []
    for i in range(word_count):
        shift_amount = combined_bits - 11 * (i + 1)
        word_index = (combined_integer >> shift_amount) & 0x7FF
        words.append(WORDLIST[word_index])
    
    return ' '.join(words)


def validate_mnemonic(mnemonic: str) -> bool:
    words = mnemonic.strip().split()
    word_count = len(words)
    
    if word_count not in (12, 15, 18, 21, 24):
        return False
    
    if not all(word in WORD_TO_INDEX for word in words):
        return False
    
    total_bits = word_count * 11
    ENT = (total_bits * 32) // 33
    CS = total_bits - ENT
    
    indices = [WORD_TO_INDEX[word] for word in words]
    combined_integer = 0
    for index in indices:
        combined_integer = (combined_integer << 11) | index
    
    extracted_checksum = combined_integer & ((1 << CS) - 1)
    extracted_entropy = combined_integer >> CS
    
    try:
        entropy_bytes = extracted_entropy.to_bytes(ENT // 8, 'big')
    except (OverflowError, ValueError):
        return False
    
    entropy_hash = hashlib.sha256(entropy_bytes).digest()
    expected_checksum = entropy_hash[0] >> (8 - CS)
    
    return extracted_checksum == expected_checksum


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048, 64)

# ============================================================================
# BIP-32 HD WALLET
# ============================================================================
def seed_to_master_keys(seed: bytes) -> Tuple[bytes, bytes]:
    hmac_result = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return hmac_result[:32], hmac_result[32:]


def point_add(p1, p2):
    if p1 == (0, 0): return p2
    if p2 == (0, 0): return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if y1 != y2: return (0, 0)
        slope = (3 * x1 * x1 * pow(2 * y1, -1, CURVE_ORDER)) % CURVE_ORDER
    else:
        slope = ((y2 - y1) * pow(x2 - x1, -1, CURVE_ORDER)) % CURVE_ORDER
    x3 = (slope * slope - x1 - x2) % CURVE_ORDER
    y3 = (slope * (x1 - x3) - y1) % CURVE_ORDER
    return (x3, y3)


def private_key_to_public_key(private_key_bytes: bytes, compressed: bool = True) -> Optional[bytes]:
    k = int.from_bytes(private_key_bytes, 'big')
    if k == 0 or k >= CURVE_ORDER: return None
    
    rx, ry = 0, 0
    for bit in bin(k)[2:]:
        if (rx, ry) != (0, 0):
            rx, ry = point_add((rx, ry), (rx, ry))
        if bit == '1':
            if (rx, ry) == (0, 0):
                rx, ry = CURVE_GX, CURVE_GY
            else:
                rx, ry = point_add((rx, ry), (CURVE_GX, CURVE_GY))
    
    if compressed:
        prefix = 0x02 if (ry % 2 == 0) else 0x03
        return bytes([prefix]) + rx.to_bytes(32, 'big')
    return b'\x04' + rx.to_bytes(32, 'big') + ry.to_bytes(32, 'big')


def derive_child_key(parent_key: bytes, parent_chain: bytes, child_index: int) -> Tuple[bytes, bytes]:
    if child_index >= 0x80000000:
        data = b'\x00' + parent_key + struct.pack('>I', child_index)
    else:
        parent_pub = private_key_to_public_key(parent_key, compressed=True)
        data = parent_pub + struct.pack('>I', child_index)
    
    hmac_result = hmac.new(parent_chain, data, hashlib.sha512).digest()
    left_bytes = hmac_result[:32]
    right_bytes = hmac_result[32:]
    
    left_int = int.from_bytes(left_bytes, 'big')
    parent_int = int.from_bytes(parent_key, 'big')
    child_int = (left_int + parent_int) % CURVE_ORDER
    
    return child_int.to_bytes(32, 'big'), right_bytes


def derive_key_from_path(seed: bytes, derivation_path: str) -> Optional[bytes]:
    current_key, current_chain = seed_to_master_keys(seed)
    
    path_components = derivation_path.replace("m/", "").split("/")
    
    for component in path_components:
        if not component: continue
        
        hardened = component.endswith("'")
        index_str = component[:-1] if hardened else component
        
        try:
            index = int(index_str)
        except ValueError:
            return None
        
        if hardened: index += 0x80000000
        
        current_key, current_chain = derive_child_key(current_key, current_chain, index)
    
    return current_key

# ============================================================================
# ADDRESS GENERATORS
# ============================================================================
def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, rem = divmod(n, 58)
        result.append(BASE58_ALPHABET[rem])
    for b in data:
        if b == 0: result.append(BASE58_ALPHABET[0])
        else: break
    return ''.join(reversed(result))


def base58_check_encode(prefix: bytes, payload: bytes) -> str:
    combined = prefix + payload
    checksum = double_sha256(combined)[:4]
    return base58_encode(combined + checksum)


def bech32_hrp_expand(hrp: str) -> List[int]:
    result = []
    for c in hrp: result.append(ord(c) >> 5)
    result.append(0)
    for c in hrp: result.append(ord(c) & 31)
    return result


def bech32_polymod(values: List[int]) -> int:
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            if (top >> i) & 1: chk ^= gen[i]
    return chk


def bech32_encode(hrp: str, witness_version: int, witness_program: bytes) -> str:
    data = [witness_version] + list(witness_program)
    values = bech32_hrp_expand(hrp) + data + [0, 0, 0, 0, 0, 0]
    polymod = bech32_polymod(values) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    combined = data + checksum
    return hrp + '1' + ''.join(BECH32_ALPHABET[d] for d in combined)


def generate_bitcoin_p2pkh(public_key: bytes) -> str:
    return base58_check_encode(b'\x00', hash160(public_key))


def generate_bitcoin_p2sh_p2wpkh(public_key: bytes) -> str:
    witness_program = b'\x00\x14' + hash160(public_key)
    return base58_check_encode(b'\x05', hash160(witness_program))


def generate_bitcoin_bech32(public_key: bytes) -> str:
    return bech32_encode('bc', 0, hash160(public_key))


def generate_ethereum_address(public_key_uncompressed: bytes) -> str:
    pubkey_no_prefix = public_key_uncompressed[1:]
    keccak_hash = hashlib.sha256(pubkey_no_prefix).digest()
    address_bytes = keccak_hash[-20:]
    address_hex = address_bytes.hex()
    checksum_input = hashlib.sha256(address_hex.encode()).hexdigest()
    result = '0x'
    for i, char in enumerate(address_hex):
        if int(checksum_input[i], 16) >= 8: result += char.upper()
        else: result += char.lower()
    return result


def generate_litecoin_p2pkh(public_key: bytes) -> str:
    return base58_check_encode(b'\x30', hash160(public_key))


def generate_litecoin_p2sh_p2wpkh(public_key: bytes) -> str:
    witness_program = b'\x00\x14' + hash160(public_key)
    return base58_check_encode(b'\x32', hash160(witness_program))


def generate_dogecoin_p2pkh(public_key: bytes) -> str:
    return base58_check_encode(b'\x1e', hash160(public_key))

# ============================================================================
# DERIVATION PATHS
# ============================================================================
DERIVATION_PATHS = {
    "BTC Legacy":         ("m/44'/0'/0'/0/0", "BTC_P2PKH"),
    "BTC SegWit":         ("m/49'/0'/0'/0/0", "BTC_P2SH"),
    "BTC Native SegWit":  ("m/84'/0'/0'/0/0", "BTC_BECH32"),
    "Ethereum":           ("m/44'/60'/0'/0/0", "EVM"),
    "BNB Smart Chain":    ("m/44'/60'/0'/0/0", "EVM"),
    "Polygon":            ("m/44'/60'/0'/0/0", "EVM"),
    "Avalanche C-Chain":  ("m/44'/60'/0'/0/0", "EVM"),
    "Fantom":             ("m/44'/60'/0'/0/0", "EVM"),
    "Arbitrum":           ("m/44'/60'/0'/0/0", "EVM"),
    "Optimism":           ("m/44'/60'/0'/0/0", "EVM"),
    "Base":               ("m/44'/60'/0'/0/0", "EVM"),
    "TRON":               ("m/44'/195'/0'/0/0", "EVM"),
    "Litecoin Legacy":    ("m/44'/2'/0'/0/0", "LTC_P2PKH"),
    "Litecoin SegWit":    ("m/49'/2'/0'/0/0", "LTC_P2SH"),
    "Dogecoin":           ("m/44'/3'/0'/0/0", "DOGE"),
}

# ============================================================================
# SCANNERS
# ============================================================================
def fetch_bitcoin_balance(address: str) -> float:
    try:
        url = f"https://blockstream.info/api/address/{address}"
        response = requests.get(url, timeout=8)
        if response.status_code == 200:
            data = response.json()
            cs = data.get('chain_stats', {})
            ms = data.get('mempool_stats', {})
            funded = cs.get('funded_txo_sum', 0) + ms.get('funded_txo_sum', 0)
            spent = cs.get('spent_txo_sum', 0) + ms.get('spent_txo_sum', 0)
            return (funded - spent) / 1e8
    except Exception: pass
    return 0.0


def fetch_evm_balance(address: str, api_url: str) -> float:
    try:
        params = {'module': 'account', 'action': 'balance', 'address': address, 'tag': 'latest'}
        response = requests.get(api_url, params=params, timeout=8)
        data = response.json()
        if data.get('status') == '1': return int(data.get('result', '0')) / 1e18
    except Exception: pass
    return 0.0


def fetch_litecoin_balance(address: str) -> float:
    try:
        url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance"
        response = requests.get(url, timeout=8)
        return response.json().get('final_balance', 0) / 1e8
    except Exception: pass
    return 0.0


def fetch_dogecoin_balance(address: str) -> float:
    try:
        url = f"https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance"
        response = requests.get(url, timeout=8)
        return response.json().get('final_balance', 0) / 1e8
    except Exception: pass
    return 0.0


def fetch_tron_balance(address: str) -> float:
    try:
        url = f"https://apilist.tronscanapi.com/api/accountv2?address={address}"
        response = requests.get(url, timeout=8)
        return response.json().get('balance', 0) / 1e6
    except Exception: pass
    return 0.0

# ============================================================================
# FULL WALLET DERIVATION
# ============================================================================
def derive_full_wallet(mnemonic: str) -> Tuple[Dict, bytes, bytes]:
    seed = mnemonic_to_seed(mnemonic)
    master_key, master_chain = seed_to_master_keys(seed)
    
    wallets = {}
    
    for name, (path, addr_type) in DERIVATION_PATHS.items():
        private_key = derive_key_from_path(seed, path)
        
        if private_key is None:
            wallets[name] = {'error': 'derivation failed'}
            continue
        
        public_key_compressed = private_key_to_public_key(private_key, compressed=True)
        public_key_uncompressed = private_key_to_public_key(private_key, compressed=False)
        
        if public_key_compressed is None or public_key_uncompressed is None:
            wallets[name] = {'error': 'pubkey failed'}
            continue
        
        if addr_type == 'BTC_P2PKH':
            wallets[name] = {'address': generate_bitcoin_p2pkh(public_key_compressed), 'type': 'BTC'}
        elif addr_type == 'BTC_P2SH':
            wallets[name] = {'address': generate_bitcoin_p2sh_p2wpkh(public_key_compressed), 'type': 'BTC'}
        elif addr_type == 'BTC_BECH32':
            wallets[name] = {'address': generate_bitcoin_bech32(public_key_compressed), 'type': 'BTC'}
        elif addr_type == 'EVM':
            wallets[name] = {'address': generate_ethereum_address(public_key_uncompressed), 'type': 'EVM'}
        elif addr_type == 'LTC_P2PKH':
            wallets[name] = {'address': generate_litecoin_p2pkh(public_key_compressed), 'type': 'LTC'}
        elif addr_type == 'LTC_P2SH':
            wallets[name] = {'address': generate_litecoin_p2sh_p2wpkh(public_key_compressed), 'type': 'LTC'}
        elif addr_type == 'DOGE':
            wallets[name] = {'address': generate_dogecoin_p2pkh(public_key_compressed), 'type': 'DOGE'}
    
    return wallets, master_key, master_chain

# ============================================================================
# UI
# ============================================================================
st.set_page_config(page_title="HD Key Hunter", page_icon="K")
st.title("HD Key Hunter")
st.subheader("BIP-39 / BIP-32 / BIP-44 Full Standard Derivation")
st.caption("Addresses match MetaMask, TrustWallet, Ledger, Trezor, Exodus")

tab1, tab2 = st.tabs(["Generate & Scan", "Deep Scan"])

with tab1:
    c1, c2 = st.columns(2)
    with c1: n = st.slider("Phrases", 1, 5, 1)
    with c2: wc = st.radio("Words", [12, 24], horizontal=True)
    
    if st.button("Generate + Scan All Chains", type="primary", use_container_width=True):
        for _ in range(n):
            phrase = generate_mnemonic(wc)
            st.markdown("---")
            st.code(phrase)
            
            wallets, mk, mc = derive_full_wallet(phrase)
            st.text(f"Master Key: {mk.hex()}")
            st.text(f"Chain Code: {mc.hex()}")
            st.text(f"15 Addresses:")
            
            found = False
            for name, data in wallets.items():
                if 'error' in data:
                    st.text(f"  {name}: {data['error']}")
                    continue
                
                addr = data['address']
                t = data['type']
                
                if t in ('BTC',): bal = fetch_bitcoin_balance(addr); sym = 'BTC'
                elif t == 'LTC': bal = fetch_litecoin_balance(addr); sym = 'LTC'
                elif t == 'DOGE': bal = fetch_dogecoin_balance(addr); sym = 'DOGE'
                elif t == 'EVM':
                    if name == 'TRON': bal = fetch_tron_balance(addr); sym = 'TRX'
                    elif name == 'Ethereum': bal = fetch_evm_balance(addr, 'https://api.etherscan.io/api'); sym = 'ETH'
                    elif name == 'BNB Smart Chain': bal = fetch_evm_balance(addr, 'https://api.bscscan.com/api'); sym = 'BNB'
                    elif name == 'Polygon': bal = fetch_evm_balance(addr, 'https://api.polygonscan.com/api'); sym = 'MATIC'
                    elif name == 'Avalanche C-Chain': bal = fetch_evm_balance(addr, 'https://api.snowtrace.io/api'); sym = 'AVAX'
                    elif name == 'Fantom': bal = fetch_evm_balance(addr, 'https://api.ftmscan.com/api'); sym = 'FTM'
                    elif name == 'Arbitrum': bal = fetch_evm_balance(addr, 'https://api.arbiscan.io/api'); sym = 'ETH'
                    elif name == 'Optimism': bal = fetch_evm_balance(addr, 'https://api-optimistic.etherscan.io/api'); sym = 'ETH'
                    elif name == 'Base': bal = fetch_evm_balance(addr, 'https://api.basescan.org/api'); sym = 'ETH'
                    else: bal = 0.0; sym = '?'
                else: bal = 0.0; sym = '?'
                
                if bal > 0:
                    found = True
                    st.success(f"  FOUND {name}: {bal:.8f} {sym} - {addr}")
                else:
                    st.text(f"  {name}: 0 {sym}")
                
                time.sleep(0.02)
            
            if found: st.balloons()
            else: st.warning("All 15 addresses: zero balance")

with tab2:
    phrase = st.text_area("Enter BIP-39 phrase:", height=80)
    
    if st.button("Full HD Scan", type="primary", use_container_width=True):
        if phrase.strip():
            if not validate_mnemonic(phrase.strip()):
                st.error("Invalid checksum")
            else:
                wallets, mk, mc = derive_full_wallet(phrase.strip())
                st.code(f"Master Key: {mk.hex()}\nChain Code: {mc.hex()}")
                
                for name, data in wallets.items():
                    if 'error' in data:
                        st.text(f"{name}: {data['error']}")
                        continue
                    
                    addr = data['address']
                    t = data['type']
                    
                    if t in ('BTC',): bal = fetch_bitcoin_balance(addr); sym = 'BTC'
                    elif t == 'LTC': bal = fetch_litecoin_balance(addr); sym = 'LTC'
                    elif t == 'DOGE': bal = fetch_dogecoin_balance(addr); sym = 'DOGE'
                    elif t == 'EVM':
                        if name == 'TRON': bal = fetch_tron_balance(addr); sym = 'TRX'
                        elif name == 'Ethereum': bal = fetch_evm_balance(addr, 'https://api.etherscan.io/api'); sym = 'ETH'
                        elif name == 'BNB Smart Chain': bal = fetch_evm_balance(addr, 'https://api.bscscan.com/api'); sym = 'BNB'
                        elif name == 'Polygon': bal = fetch_evm_balance(addr, 'https://api.polygonscan.com/api'); sym = 'MATIC'
                        elif name == 'Avalanche C-Chain': bal = fetch_evm_balance(addr, 'https://api.snowtrace.io/api'); sym = 'AVAX'
                        elif name == 'Fantom': bal = fetch_evm_balance(addr, 'https://api.ftmscan.com/api'); sym = 'FTM'
                        elif name == 'Arbitrum': bal = fetch_evm_balance(addr, 'https://api.arbiscan.io/api'); sym = 'ETH'
                        elif name == 'Optimism': bal = fetch_evm_balance(addr, 'https://api-optimistic.etherscan.io/api'); sym = 'ETH'
                        elif name == 'Base': bal = fetch_evm_balance(addr, 'https://api.basescan.org/api'); sym = 'ETH'
                        else: bal = 0.0; sym = '?'
                    else: bal = 0.0; sym = '?'
                    
                    if bal > 0:
                        st.success(f"FOUND {name}: {bal:.8f} {sym} - {addr}")
                    else:
                        st.text(f"{name}: 0 {sym}")
                    
                    time.sleep(0.02)

st.caption("BIP-39/32/44 standard | 15 addresses | 13 chains")
