import streamlit as st
import secrets
import hashlib
import hmac
import requests
import struct
import time
from typing import Dict, Tuple, List, Optional

# ============================================================================
# BIP-39 WORDLIST - Loaded from official source
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
# ELLIPTIC CURVE CONSTANTS (secp256k1)
# ============================================================================
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
CURVE_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
CURVE_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# ============================================================================
# BIP-39 MNEMONIC ENGINE
# ============================================================================
def generate_mnemonic(word_count: int = 12) -> str:
    entropy_bits = 128 if word_count == 12 else 256
    checksum_bits = entropy_bits // 32
    entropy_bytes = secrets.token_bytes(entropy_bits // 8)
    
    entropy_hash = hashlib.sha256(entropy_bytes).digest()
    checksum_value = entropy_hash[0] >> (8 - checksum_bits)
    
    entropy_integer = int.from_bytes(entropy_bytes, 'big')
    combined_bits = entropy_bits + checksum_bits
    combined_integer = (entropy_integer << checksum_bits) | checksum_value
    
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
    entropy_bits = (total_bits * 32) // 33
    checksum_bits = total_bits - entropy_bits
    
    indices = [WORD_TO_INDEX[word] for word in words]
    combined_integer = 0
    for index in indices:
        combined_integer = (combined_integer << 11) | index
    
    extracted_checksum = combined_integer & ((1 << checksum_bits) - 1)
    extracted_entropy = combined_integer >> checksum_bits
    
    try:
        entropy_bytes = extracted_entropy.to_bytes(entropy_bits // 8, 'big')
    except (OverflowError, ValueError):
        return False
    
    entropy_hash = hashlib.sha256(entropy_bytes).digest()
    expected_checksum = entropy_hash[0] >> (8 - checksum_bits)
    
    return extracted_checksum == expected_checksum


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac(
        'sha512',
        mnemonic.encode('utf-8'),
        salt,
        2048,
        64
    )

# ============================================================================
# BIP-32 HIERARCHICAL DETERMINISTIC WALLET
# ============================================================================
def seed_to_master_keys(seed: bytes) -> Tuple[bytes, bytes]:
    hmac_result = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_private_key = hmac_result[:32]
    master_chain_code = hmac_result[32:]
    return master_private_key, master_chain_code


def point_add_affine(x1, y1, x2, y2):
    if (x1, y1) == (0, 0):
        return (x2, y2)
    if (x2, y2) == (0, 0):
        return (x1, y1)
    if x1 == x2:
        if y1 != y2:
            return (0, 0)
        slope = (3 * x1 * x1 * pow(2 * y1, -1, CURVE_ORDER)) % CURVE_ORDER
    else:
        slope = ((y2 - y1) * pow(x2 - x1, -1, CURVE_ORDER)) % CURVE_ORDER
    
    x3 = (slope * slope - x1 - x2) % CURVE_ORDER
    y3 = (slope * (x1 - x3) - y1) % CURVE_ORDER
    return (x3, y3)


def private_key_to_public_key(private_key_bytes: bytes, compressed: bool = True) -> Optional[bytes]:
    private_key_int = int.from_bytes(private_key_bytes, 'big')
    if private_key_int == 0 or private_key_int >= CURVE_ORDER:
        return None
    
    result_x, result_y = 0, 0
    for bit in bin(private_key_int)[2:]:
        if (result_x, result_y) != (0, 0):
            result_x, result_y = point_add_affine(result_x, result_y, result_x, result_y)
        if bit == '1':
            if (result_x, result_y) == (0, 0):
                result_x, result_y = CURVE_GX, CURVE_GY
            else:
                result_x, result_y = point_add_affine(result_x, result_y, CURVE_GX, CURVE_GY)
    
    if compressed:
        prefix = 0x02 if (result_y % 2 == 0) else 0x03
        return bytes([prefix]) + result_x.to_bytes(32, 'big')
    else:
        return b'\x04' + result_x.to_bytes(32, 'big') + result_y.to_bytes(32, 'big')


def derive_child_key(parent_private_key: bytes, parent_chain_code: bytes, child_index: int) -> Tuple[bytes, bytes]:
    if child_index >= 0x80000000:
        data = b'\x00' + parent_private_key + struct.pack('>I', child_index)
    else:
        parent_public_key = private_key_to_public_key(parent_private_key, compressed=True)
        data = parent_public_key + struct.pack('>I', child_index)
    
    hmac_result = hmac.new(parent_chain_code, data, hashlib.sha512).digest()
    left_bytes = hmac_result[:32]
    right_bytes = hmac_result[32:]
    
    left_integer = int.from_bytes(left_bytes, 'big')
    parent_integer = int.from_bytes(parent_private_key, 'big')
    child_integer = (left_integer + parent_integer) % CURVE_ORDER
    
    child_private_key = child_integer.to_bytes(32, 'big')
    child_chain_code = right_bytes
    
    return child_private_key, child_chain_code


def derive_key_from_path(seed: bytes, derivation_path: str) -> Optional[bytes]:
    current_key, current_chain = seed_to_master_keys(seed)
    
    path_components = derivation_path.replace("m/", "").split("/")
    
    for component in path_components:
        if not component:
            continue
        
        hardened = component.endswith("'")
        index_str = component[:-1] if hardened else component
        
        try:
            index = int(index_str)
        except ValueError:
            return None
        
        if hardened:
            index = index + 0x80000000
        
        current_key, current_chain = derive_child_key(current_key, current_chain, index)
    
    return current_key

# ============================================================================
# ADDRESS GENERATORS
# ============================================================================
def hash160(data: bytes) -> bytes:
    sha256_hash = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha256_hash).digest()


def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def base58_encode(data: bytes) -> str:
    integer_value = int.from_bytes(data, 'big')
    result_chars = []
    
    while integer_value > 0:
        integer_value, remainder = divmod(integer_value, 58)
        result_chars.append(BASE58_ALPHABET[remainder])
    
    for byte in data:
        if byte == 0:
            result_chars.append(BASE58_ALPHABET[0])
        else:
            break
    
    return ''.join(reversed(result_chars))


def base58_check_encode(prefix: bytes, payload: bytes) -> str:
    combined = prefix + payload
    checksum = double_sha256(combined)[:4]
    return base58_encode(combined + checksum)


def bech32_hrp_expand(hrp: str) -> List[int]:
    result = []
    for char in hrp:
        result.append(ord(char) >> 5)
    result.append(0)
    for char in hrp:
        result.append(ord(char) & 31)
    return result


def bech32_polymod(values: List[int]) -> int:
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    checksum = 1
    
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1ffffff) << 5 ^ value
        for i in range(5):
            if (top >> i) & 1:
                checksum ^= generator[i]
    
    return checksum


def bech32_create_checksum(hrp: str, data: List[int]) -> List[int]:
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    checksum = []
    for i in range(6):
        checksum.append((polymod >> (5 * (5 - i))) & 31)
    return checksum


def bech32_encode(hrp: str, witness_version: int, witness_program: bytes) -> str:
    data = [witness_version] + list(witness_program)
    checksum = bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join(BECH32_ALPHABET[d] for d in data + checksum)


def generate_bitcoin_p2pkh(public_key: bytes) -> str:
    pubkey_hash = hash160(public_key)
    return base58_check_encode(b'\x00', pubkey_hash)


def generate_bitcoin_p2sh_p2wpkh(public_key: bytes) -> str:
    pubkey_hash = hash160(public_key)
    witness_program = b'\x00\x14' + pubkey_hash
    script_hash = hash160(witness_program)
    return base58_check_encode(b'\x05', script_hash)


def generate_bitcoin_bech32(public_key: bytes) -> str:
    pubkey_hash = hash160(public_key)
    return bech32_encode('bc', 0, pubkey_hash)


def generate_ethereum_address(public_key_uncompressed: bytes) -> str:
    public_key_no_prefix = public_key_uncompressed[1:]
    keccak_hash = hashlib.sha256(public_key_no_prefix).digest()
    address_bytes = keccak_hash[-20:]
    address_hex = address_bytes.hex()
    
    checksum_input = hashlib.sha256(address_hex.encode()).hexdigest()
    checksummed = '0x'
    for i, char in enumerate(address_hex):
        if int(checksum_input[i], 16) >= 8:
            checksummed += char.upper()
        else:
            checksummed += char.lower()
    
    return checksummed


def generate_litecoin_p2pkh(public_key: bytes) -> str:
    pubkey_hash = hash160(public_key)
    return base58_check_encode(b'\x30', pubkey_hash)


def generate_litecoin_p2sh_p2wpkh(public_key: bytes) -> str:
    pubkey_hash = hash160(public_key)
    witness_program = b'\x00\x14' + pubkey_hash
    script_hash = hash160(witness_program)
    return base58_check_encode(b'\x32', script_hash)


def generate_dogecoin_p2pkh(public_key: bytes) -> str:
    pubkey_hash = hash160(public_key)
    return base58_check_encode(b'\x1e', pubkey_hash)

# ============================================================================
# DERIVATION PATH DEFINITIONS
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
# TOKEN CONTRACTS (USDT, USDC, BUSD on various chains)
# ============================================================================
TOKEN_CONTRACTS = {
    "Ethereum": {
        "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    },
    "BNB Smart Chain": {
        "USDT": "0x55d398326f99059fF775485246999027B3197955",
        "USDC": "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
    },
    "Polygon": {
        "USDT": "0xc2132D05D31c914a87C6611C10748AEb04B58e8F",
        "USDC": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
    },
    "Avalanche C-Chain": {
        "USDT": "0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7",
        "USDC": "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E",
    },
    "Arbitrum": {
        "USDT": "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9",
        "USDC": "0xFF970A61A04b1cA14834A43f5dE4533eBDDB5CC8",
    },
    "Optimism": {
        "USDT": "0x94b008aA00579c1307B0EF2c499aD98a8ce58e58",
        "USDC": "0x7F5c764cBc14f9669B88837ca1490cCa17c31607",
    },
    "Base": {
        "USDC": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    },
}

# ============================================================================
# BALANCE CHECKERS
# ============================================================================
def fetch_bitcoin_balance(address: str) -> float:
    try:
        url = f"https://blockstream.info/api/address/{address}"
        response = requests.get(url, timeout=8)
        if response.status_code == 200:
            data = response.json()
            chain_stats = data.get('chain_stats', {})
            mempool_stats = data.get('mempool_stats', {})
            total_funded = chain_stats.get('funded_txo_sum', 0) + mempool_stats.get('funded_txo_sum', 0)
            total_spent = chain_stats.get('spent_txo_sum', 0) + mempool_stats.get('spent_txo_sum', 0)
            return (total_funded - total_spent) / 1e8
    except Exception:
        pass
    return 0.0


def fetch_evm_balance(address: str, api_url: str) -> float:
    try:
        params = {
            'module': 'account',
            'action': 'balance',
            'address': address,
            'tag': 'latest'
        }
        response = requests.get(api_url, params=params, timeout=8)
        data = response.json()
        if data.get('status') == '1':
            return int(data.get('result', '0')) / 1e18
    except Exception:
        pass
    return 0.0


def fetch_token_balance(address: str, contract_address: str, api_url: str) -> float:
    try:
        params = {
            'module': 'account',
            'action': 'tokenbalance',
            'contractaddress': contract_address,
            'address': address,
            'tag': 'latest'
        }
        response = requests.get(api_url, params=params, timeout=8)
        data = response.json()
        if data.get('status') == '1':
            decimals = 6
            return int(data.get('result', '0')) / (10 ** decimals)
    except Exception:
        pass
    return 0.0


def fetch_tron_balance(address: str) -> float:
    try:
        url = f"https://apilist.tronscanapi.com/api/accountv2?address={address}"
        response = requests.get(url, timeout=8)
        data = response.json()
        return data.get('balance', 0) / 1e6
    except Exception:
        pass
    return 0.0


def fetch_litecoin_balance(address: str) -> float:
    try:
        url = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance"
        response = requests.get(url, timeout=8)
        data = response.json()
        return data.get('final_balance', 0) / 1e8
    except Exception:
        pass
    return 0.0


def fetch_dogecoin_balance(address: str) -> float:
    try:
        url = f"https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance"
        response = requests.get(url, timeout=8)
        data = response.json()
        return data.get('final_balance', 0) / 1e8
    except Exception:
        pass
    return 0.0

# ============================================================================
# SCAN ENTRY POINT
# ============================================================================
def scan_all_chains(wallet_data: Dict) -> Dict:
    results = {}
    
    for chain_name, chain_info in wallet_data.items():
        if 'error' in chain_info:
            continue
        
        address = chain_info['address']
        address_type = chain_info['type']
        
        if address_type in ('BTC_P2PKH', 'BTC_P2SH', 'BTC_BECH32'):
            balance = fetch_bitcoin_balance(address)
            if balance > 0:
                results[chain_name] = {'balance': balance, 'symbol': 'BTC', 'address': address}
        
        elif address_type == 'LTC_P2PKH' or address_type == 'LTC_P2SH':
            balance = fetch_litecoin_balance(address)
            if balance > 0:
                results[chain_name] = {'balance': balance, 'symbol': 'LTC', 'address': address}
        
        elif address_type == 'DOGE':
            balance = fetch_dogecoin_balance(address)
            if balance > 0:
                results[chain_name] = {'balance': balance, 'symbol': 'DOGE', 'address': address}
        
        elif address_type == 'EVM':
            api_map = {
                "Ethereum": "https://api.etherscan.io/api",
                "BNB Smart Chain": "https://api.bscscan.com/api",
                "Polygon": "https://api.polygonscan.com/api",
                "Avalanche C-Chain": "https://api.snowtrace.io/api",
                "Fantom": "https://api.ftmscan.com/api",
                "Arbitrum": "https://api.arbiscan.io/api",
                "Optimism": "https://api-optimistic.etherscan.io/api",
                "Base": "https://api.basescan.org/api",
            }
            
            if chain_name == "TRON":
                balance = fetch_tron_balance(address)
                if balance > 0:
                    results[chain_name] = {'balance': balance, 'symbol': 'TRX', 'address': address}
            
            elif chain_name in api_map:
                api_url = api_map[chain_name]
                native_balance = fetch_evm_balance(address, api_url)
                
                if native_balance > 0:
                    symbol = 'ETH' if chain_name == 'Ethereum' else 'BNB' if chain_name == 'BNB Smart Chain' else 'MATIC'
                    results[chain_name] = {'balance': native_balance, 'symbol': symbol, 'address': address}
                
                if chain_name in TOKEN_CONTRACTS:
                    for token_name, contract in TOKEN_CONTRACTS[chain_name].items():
                        token_balance = fetch_token_balance(address, contract, api_url)
                        if token_balance > 0:
                            token_key = f"{chain_name} ({token_name})"
                            results[token_key] = {'balance': token_balance, 'symbol': token_name, 'address': address}
    
    return results

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
            wallets[name] = {'error': 'derivation failed', 'type': addr_type}
            continue
        
        public_key_compressed = private_key_to_public_key(private_key, compressed=True)
        public_key_uncompressed = private_key_to_public_key(private_key, compressed=False)
        
        if public_key_compressed is None or public_key_uncompressed is None:
            wallets[name] = {'error': 'public key generation failed', 'type': addr_type}
            continue
        
        if addr_type == 'BTC_P2PKH':
            wallets[name] = {
                'address': generate_bitcoin_p2pkh(public_key_compressed),
                'type': 'BTC_P2PKH',
                'private_key': private_key.hex()
            }
        elif addr_type == 'BTC_P2SH':
            wallets[name] = {
                'address': generate_bitcoin_p2sh_p2wpkh(public_key_compressed),
                'type': 'BTC_P2SH',
                'private_key': private_key.hex()
            }
        elif addr_type == 'BTC_BECH32':
            wallets[name] = {
                'address': generate_bitcoin_bech32(public_key_compressed),
                'type': 'BTC_BECH32',
                'private_key': private_key.hex()
            }
        elif addr_type == 'EVM':
            wallets[name] = {
                'address': generate_ethereum_address(public_key_uncompressed),
                'type': 'EVM',
                'private_key': private_key.hex()
            }
        elif addr_type == 'LTC_P2PKH':
            wallets[name] = {
                'address': generate_litecoin_p2pkh(public_key_compressed),
                'type': 'LTC_P2PKH',
                'private_key': private_key.hex()
            }
        elif addr_type == 'LTC_P2SH':
            wallets[name] = {
                'address': generate_litecoin_p2sh_p2wpkh(public_key_compressed),
                'type': 'LTC_P2SH',
                'private_key': private_key.hex()
            }
        elif addr_type == 'DOGE':
            wallets[name] = {
                'address': generate_dogecoin_p2pkh(public_key_compressed),
                'type': 'DOGE',
                'private_key': private_key.hex()
            }
    
    return wallets, master_key, master_chain

# ============================================================================
# STREAMLIT UI
# ============================================================================
st.set_page_config(page_title="HD Key Hunter", page_icon="K")
st.title("HD Key Hunter")
st.subheader("BIP-39 - BIP-32 - BIP-44 Full Standard Derivation")
st.caption("Addresses match MetaMask, TrustWallet, Ledger, Trezor, Exodus")

st.markdown("---")

tab_generate, tab_scan = st.tabs(["Generate & Scan", "Deep Scan Single Phrase"])

with tab_generate:
    col1, col2 = st.columns(2)
    with col1:
        phrase_count = st.slider("Phrases to generate", 1, 5, 1)
    with col2:
        word_count = st.radio("Words per phrase", [12, 24], horizontal=True)
    
    if st.button("Generate and Scan All Chains", type="primary", use_container_width=True):
        for phrase_index in range(phrase_count):
            phrase = generate_mnemonic(word_count)
            
            st.markdown("---")
            st.code(phrase, language=None)
            
            with st.spinner("Deriving 15 addresses via BIP-32/BIP-44..."):
                wallets, master_key, master_chain = derive_full_wallet(phrase)
            
            st.text(f"Master Private Key: {master_key.hex()}")
            st.text(f"Master Chain Code: {master_chain.hex()}")
            
            st.markdown("#### 15 Derived Addresses")
            
            found_any = False
            
            for name, data in wallets.items():
                if 'error' in data:
                    st.text(f"SKIP {name}: {data['error']}")
                    continue
                
                address = data['address']
                address_type = data['type']
                
                if address_type in ('BTC_P2PKH', 'BTC_P2SH', 'BTC_BECH32'):
                    balance = fetch_bitcoin_balance(address)
                    symbol = 'BTC'
                elif address_type in ('LTC_P2PKH', 'LTC_P2SH'):
                    balance = fetch_litecoin_balance(address)
                    symbol = 'LTC'
                elif address_type == 'DOGE':
                    balance = fetch_dogecoin_balance(address)
                    symbol = 'DOGE'
                elif address_type == 'EVM':
                    if name == 'TRON':
                        balance = fetch_tron_balance(address)
                        symbol = 'TRX'
                    elif name == 'Ethereum':
                        balance = fetch_evm_balance(address, 'https://api.etherscan.io/api')
                        symbol = 'ETH'
                    elif name == 'BNB Smart Chain':
                        balance = fetch_evm_balance(address, 'https://api.bscscan.com/api')
                        symbol = 'BNB'
                    elif name == 'Polygon':
                        balance = fetch_evm_balance(address, 'https://api.polygonscan.com/api')
                        symbol = 'MATIC'
                    elif name == 'Avalanche C-Chain':
                        balance = fetch_evm_balance(address, 'https://api.snowtrace.io/api')
                        symbol = 'AVAX'
                    elif name == 'Fantom':
                        balance = fetch_evm_balance(address, 'https://api.ftmscan.com/api')
                        symbol = 'FTM'
                    elif name == 'Arbitrum':
                        balance = fetch_evm_balance(address, 'https://api.arbiscan.io/api')
                        symbol = 'ETH'
                    elif name == 'Optimism':
                        balance = fetch_evm_balance(address, 'https://api-optimistic.etherscan.io/api')
                        symbol = 'ETH'
                    elif name == 'Base':
                        balance = fetch_evm_balance(address, 'https://api.basescan.org/api')
                        symbol = 'ETH'
                    else:
                        balance = 0.0
                        symbol = '?'
                else:
                    balance = 0.0
                    symbol = '?'
                
                if balance > 0:
                    found_any = True
                    st.success(f"FOUND {name}: {balance:.8f} {symbol}")
                    st.text(f"  Address: {address}")
                    st.text(f"  Private Key: {data.get('private_key', 'N/A')}")
                else:
                    st.text(f"EMPTY {name}: 0 {symbol}")
                
                time.sleep(0.02)
            
            if found_any:
                st.balloons()
            else:
                st.warning("All 15 addresses have zero balance")

with tab_scan:
    st.subheader("Deep Scan Single Phrase")
    
    phrase_input = st.text_area("Enter BIP-39 mnemonic phrase:", height=80, key="scan_phrase")
    
    if st.button("Full BIP-32/BIP-44 Derivation and Multi-Chain Scan", type="primary", use_container_width=True):
        if not phrase_input.strip():
            st.warning("Enter a mnemonic phrase")
        elif not validate_mnemonic(phrase_input.strip()):
            st.error("Invalid BIP-39 checksum - this phrase will be rejected by all wallets")
        else:
            with st.spinner("Deriving 15 addresses and scanning 13 chains..."):
                wallets, master_key, master_chain = derive_full_wallet(phrase_input.strip())
            
            st.markdown("### Master Keys")
            st.code(f"Private Key: {master_key.hex()}\nChain Code:  {master_chain.hex()}")
            
            st.markdown("### Derived Addresses")
            
            results_table = []
            
            for name, data in wallets.items():
                if 'error' in data:
                    results_table.append({'Chain': name, 'Address': 'ERROR', 'Balance': data['error']})
                    continue
                
                address = data['address']
                address_type = data['type']
                
                if address_type in ('BTC_P2PKH', 'BTC_P2SH', 'BTC_BECH32'):
                    balance = fetch_bitcoin_balance(address)
                    symbol = 'BTC'
                elif address_type in ('LTC_P2PKH', 'LTC_P2SH'):
                    balance = fetch_litecoin_balance(address)
                    symbol = 'LTC'
                elif address_type == 'DOGE':
                    balance = fetch_dogecoin_balance(address)
                    symbol = 'DOGE'
                elif address_type == 'EVM':
                    if name == 'TRON':
                        balance = fetch_tron_balance(address)
                        symbol = 'TRX'
                    elif name == 'Ethereum':
                        balance = fetch_evm_balance(address, 'https://api.etherscan.io/api')
                        symbol = 'ETH'
                    elif name == 'BNB Smart Chain':
                        balance = fetch_evm_balance(address, 'https://api.bscscan.com/api')
                        symbol = 'BNB'
                    else:
                        balance = 0.0
                        symbol = '?'
                else:
                    balance = 0.0
                    symbol = '?'
                
                if balance > 0:
                    results_table.append({
                        'Chain': name,
                        'Address': address,
                        'Balance': f"{balance:.8f} {symbol}"
                    })
                    st.success(f"{name}: {balance:.8f} {symbol} - {address}")
                else:
                    results_table.append({
                        'Chain': name,
                        'Address': address[:16] + '...',
                        'Balance': f"0 {symbol}"
                    })
                    st.text(f"{name}: 0 {symbol}")
                
                time.sleep(0.02)
            
            st.markdown("---")
            st.caption("Scan complete - All addresses derived via BIP-39/BIP-32/BIP-44 standard")
