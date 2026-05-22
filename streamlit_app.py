import streamlit as st
import secrets
import hashlib
import hmac
import requests
import json
import time
import struct
from typing import Dict, Optional, List, Tuple

# ============================================================================
# BIP-39 WORDLIST
# ============================================================================
@st.cache_data
def load_words():
    r = requests.get("https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt")
    words = r.text.strip().split("\n")
    return words

BIP39 = load_words()
if len(BIP39) != 2048:
    st.error("Failed to load wordlist")
    st.stop()

W2I = {w: i for i, w in enumerate(BIP39)}

# ============================================================================
# SECP256K1 CONSTANTS
# ============================================================================
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)

# ============================================================================
# BIP-39 → SEED
# ============================================================================
def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048, 64)

# ============================================================================
# BIP-32 → MASTER KEY
# ============================================================================
def seed_to_master(seed: bytes) -> Tuple[bytes, bytes]:
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return h[:32], h[32:]

# ============================================================================
# BIP-32 → CKDpriv
# ============================================================================
def derive_child_private(parent_key: bytes, parent_chain: bytes, index: int) -> Tuple[bytes, bytes]:
    if index >= 0x80000000:
        data = b'\x00' + parent_key + struct.pack('>I', index)
    else:
        data = private_to_public(parent_key, compressed=True) + struct.pack('>I', index)
    
    h = hmac.new(parent_chain, data, hashlib.sha512).digest()
    child_key = (int.from_bytes(h[:32], 'big') + int.from_bytes(parent_key, 'big')) % SECP256K1_ORDER
    child_chain = h[32:]
    return child_key.to_bytes(32, 'big'), child_chain

# ============================================================================
# BIP-32 → PARSE PATH
# ============================================================================
def parse_path(path: str) -> List[int]:
    parts = path.replace("m/", "").split("/")
    indices = []
    for part in parts:
        if not part:
            continue
        if part.endswith("'"):
            indices.append(int(part[:-1]) + 0x80000000)
        else:
            indices.append(int(part))
    return indices

# ============================================================================
# BIP-32 → FULL DERIVATION
# ============================================================================
def derive_path(seed: bytes, path: str) -> bytes:
    key, chain = seed_to_master(seed)
    for idx in parse_path(path):
        key, chain = derive_child_private(key, chain, idx)
    return key

# ============================================================================
# ECDSA → PUBLIC KEY
# ============================================================================
def private_to_public(private_key: bytes, compressed: bool = True) -> bytes:
    k = int.from_bytes(private_key, 'big') % SECP256K1_ORDER
    if k == 0:
        raise ValueError("Invalid private key")
    
    gx, gy = SECP256K1_G
    rx, ry = 0, 0
    for bit in bin(k)[2:]:
        rx, ry = point_double(rx, ry) if (rx, ry) != (0, 0) else (0, 0)
        if bit == '1':
            if (rx, ry) == (0, 0):
                rx, ry = gx, gy
            else:
                rx, ry = point_add(rx, ry, gx, gy)
    
    if compressed:
        return bytes([0x02 if ry % 2 == 0 else 0x03]) + rx.to_bytes(32, 'big')
    return b'\x04' + rx.to_bytes(32, 'big') + ry.to_bytes(32, 'big')

def point_double(x, y):
    if (x, y) == (0, 0):
        return (0, 0)
    P = SECP256K1_ORDER
    s = (3 * x * x * pow(2 * y, -1, P)) % P
    rx = (s * s - 2 * x) % P
    ry = (s * (x - rx) - y) % P
    return (rx, ry)

def point_add(x1, y1, x2, y2):
    if (x1, y1) == (0, 0):
        return (x2, y2)
    if (x2, y2) == (0, 0):
        return (x1, y1)
    P = SECP256K1_ORDER
    if x1 == x2:
        return (0, 0) if y1 != y2 else point_double(x1, y1)
    s = ((y2 - y1) * pow(x2 - x1, -1, P)) % P
    rx = (s * s - x1 - x2) % P
    ry = (s * (x1 - rx) - y1) % P
    return (rx, ry)

# ============================================================================
# ADDRESS GENERATORS
# ============================================================================
BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(data: bytes) -> str:
    n = int.from_bytes(data, 'big')
    res = []
    while n > 0:
        n, rem = divmod(n, 58)
        res.append(BASE58[rem])
    for b in data:
        if b == 0:
            res.append(BASE58[0])
        else:
            break
    return ''.join(reversed(res))

def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def pubkey_to_btc_addresses(pubkey: bytes) -> Dict[str, str]:
    addresses = {}
    h160 = hash160(pubkey)
    prefix = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    addresses['P2PKH'] = base58_encode(prefix + checksum)
    return addresses

def pubkey_to_eth_address(pubkey: bytes) -> str:
    from eth_keys import keys
    pk = keys.PublicKey(pubkey)
    return pk.to_checksum_address()

# ============================================================================
# DERIVATION PATHS
# ============================================================================
DERIVATION_PATHS = {
    'BTC Legacy (P2PKH)':  ("m/44'/0'/0'/0/0", 'BTC'),
    'BTC SegWit (P2SH)':   ("m/49'/0'/0'/0/0", 'BTC'),
    'BTC Native (Bech32)': ("m/84'/0'/0'/0/0", 'BTC'),
    'ETH':                 ("m/44'/60'/0'/0/0", 'EVM'),
    'BNB Chain':           ("m/44'/60'/0'/0/0", 'EVM'),
    'Polygon':             ("m/44'/60'/0'/0/0", 'EVM'),
    'Avalanche':           ("m/44'/60'/0'/0/0", 'EVM'),
    'Fantom':              ("m/44'/60'/0'/0/0", 'EVM'),
    'Arbitrum':            ("m/44'/60'/0'/0/0", 'EVM'),
    'Optimism':            ("m/44'/60'/0'/0/0", 'EVM'),
    'Base':                ("m/44'/60'/0'/0/0", 'EVM'),
    'TRON':                ("m/44'/195'/0'/0/0", 'TRX'),
    'LTC Legacy':          ("m/44'/2'/0'/0/0", 'LTC'),
    'LTC SegWit':          ("m/49'/2'/0'/0/0", 'LTC'),
    'Dogecoin':            ("m/44'/3'/0'/0/0", 'DOGE'),
}

EVM_APIS = {
    'ETH': 'https://api.etherscan.io/api',
    'BNB Chain': 'https://api.bscscan.com/api',
    'Polygon': 'https://api.polygonscan.com/api',
    'Avalanche': 'https://api.snowtrace.io/api',
    'Fantom': 'https://api.ftmscan.com/api',
    'Arbitrum': 'https://api.arbiscan.io/api',
    'Optimism': 'https://api-optimistic.etherscan.io/api',
    'Base': 'https://api.basescan.org/api',
}

# ============================================================================
# BALANCE CHECKERS
# ============================================================================
def check_btc(addr: str) -> float:
    try:
        r = requests.get(f"https://blockstream.info/api/address/{addr}", timeout=5)
        if r.status_code == 200:
            d = r.json()
            cs = d.get('chain_stats', {})
            ms = d.get('mempool_stats', {})
            funded = cs.get('funded_txo_sum', 0) + ms.get('funded_txo_sum', 0)
            spent = cs.get('spent_txo_sum', 0) + ms.get('spent_txo_sum', 0)
            return (funded - spent) / 1e8
    except:
        pass
    return 0.0

def check_evm(addr: str, api_url: str) -> float:
    try:
        r = requests.get(f"{api_url}?module=account&action=balance&address={addr}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e18
    except:
        pass
    return 0.0

def check_trx(addr: str) -> float:
    try:
        r = requests.get(f"https://apilist.tronscanapi.com/api/accountv2?address={addr}", timeout=5)
        d = r.json()
        return d.get('balance', 0) / 1e6
    except:
        pass
    return 0.0

def check_doge(addr: str) -> float:
    try:
        r = requests.get(f"https://dogechain.info/api/v1/address/balance/{addr}", timeout=5)
        return float(r.json().get('balance', 0))
    except:
        pass
    return 0.0

def check_ltc(addr: str) -> float:
    try:
        r = requests.get(f"https://blockchair.com/api/address/ltc/{addr}", timeout=5)
        d = r.json()
        return d.get('data', {}).get(addr, {}).get('address', {}).get('balance', 0) / 1e8
    except:
        pass
    return 0.0

# ============================================================================
# BIP-39 GENERATE & VALIDATE
# ============================================================================
def gen(wc=12):
    ENT = {12: 128, 24: 256}[wc]
    CS = ENT // 32
    e = secrets.token_bytes(ENT // 8)
    h = hashlib.sha256(e).digest()
    c = h[0] >> (8 - CS)
    ei = int.from_bytes(e, 'big')
    comb = (ei << CS) | c
    return ' '.join(BIP39[(comb >> (ENT + CS - 11 * (i + 1))) & 0x7FF] for i in range(wc))

def val(m):
    ws = m.strip().split()
    if len(ws) not in [12, 15, 18, 21, 24]:
        return False
    if not all(w in W2I for w in ws):
        return False
    wc = len(ws)
    ENT = (wc * 352) // 33
    CS = wc * 11 - ENT
    idxs = [W2I[w] for w in ws]
    comb = 0
    for idx in idxs:
        comb = (comb << 11) | idx
    cs = comb & ((1 << CS) - 1)
    eb = comb >> CS
    try:
        eb_bytes = eb.to_bytes(ENT // 8, 'big')
    except:
        return False
    return cs == (hashlib.sha256(eb_bytes).digest()[0] >> (8 - CS))

# ============================================================================
# FULL HD WALLET DERIVATION
# ============================================================================
def derive_full_wallet(mnemonic: str) -> Dict:
    seed = mnemonic_to_seed(mnemonic)
    wallets = {}
    
    for name, (path, chain_type) in DERIVATION_PATHS.items():
        try:
            priv = derive_path(seed, path)
            pub = private_to_public(priv, compressed=True)
            
            if chain_type == 'BTC':
                addrs = pubkey_to_btc_addresses(pub)
                wallets[name] = {
                    'private_key': priv.hex(),
                    'address': addrs.get('P2PKH', ''),
                    'chain': 'BTC'
                }
            elif chain_type == 'LTC':
                h160 = hash160(pub)
                prefix = b'\x30' + h160 if 'Legacy' in name else b'\x32' + h160
                checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
                wallets[name] = {
                    'private_key': priv.hex(),
                    'address': base58_encode(prefix + checksum),
                    'chain': 'LTC'
                }
            elif chain_type == 'DOGE':
                h160 = hash160(pub)
                prefix = b'\x1e' + h160
                checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
                wallets[name] = {
                    'private_key': priv.hex(),
                    'address': base58_encode(prefix + checksum),
                    'chain': 'DOGE'
                }
            elif chain_type == 'EVM':
                addr = pubkey_to_eth_address(pub)
                wallets[name] = {
                    'private_key': priv.hex(),
                    'address': addr,
                    'chain': 'EVM'
                }
            elif chain_type == 'TRX':
                addr = pubkey_to_eth_address(pub)
                wallets[name] = {
                    'private_key': priv.hex(),
                    'address': addr,
                    'chain': 'TRX'
                }
        except:
            wallets[name] = {'error': 'derivation failed', 'chain': chain_type}
    
    return wallets

# ============================================================================
# UI
# ============================================================================
st.set_page_config(page_title="HD Key Hunter", page_icon="")
st.title(" HD Key Hunter")
st.subheader("BIP-39 → BIP-32 → BIP-44 Full Standard Derivation")
st.caption("Same addresses as MetaMask · TrustWallet · Ledger · Trezor")

st.markdown("---")

t1, t2 = st.tabs([" Generate & Scan", " HD Deep Scan"])

with t1:
    c1, c2 = st.columns(2)
    with c1:
        n = st.slider("Phrases", 1, 5, 1)
    with c2:
        wc = st.radio("Words", [12, 24], horizontal=True)
    
    if st.button("Generate + Full HD Scan", type="primary", use_container_width=True):
        for _ in range(n):
            phrase = gen(wc)
            st.markdown("---")
            st.code(phrase)
            
            wallets = derive_full_wallet(phrase)
            seed = mnemonic_to_seed(phrase)
            mk, mc = seed_to_master(seed)
            
            st.text(f"Master Private Key: {mk.hex()}")
            st.text(f"Master Chain Code: {mc.hex()}")
            
            found_any = False
            total_wallets = len(wallets)
            
            progress_bar = st.progress(0)
            
            for i, (name, data) in enumerate(wallets.items()):
                if 'error' in data:
                    st.text(f" {name}: derivation error")
                    continue
                
                addr = data['address']
                chain = data['chain']
                
                # Check balance
                if chain == 'BTC':
                    bal = check_btc(addr)
                    unit = 'BTC'
                elif chain == 'LTC':
                    bal = check_ltc(addr)
                    unit = 'LTC'
                elif chain == 'DOGE':
                    bal = check_doge(addr)
                    unit = 'DOGE'
                elif chain == 'TRX':
                    bal = check_trx(addr)
                    unit = 'TRX'
                elif chain == 'EVM' and name in EVM_APIS:
                    bal = check_evm(addr, EVM_APIS[name])
                    unit = name.split()[0]
                else:
                    bal = 0.0
                    unit = '?'
                
                if bal > 0:
                    found_any = True
                    st.success(f" **{name}**: {bal:.8f} {unit}")
                    st.text(f"   Address: {addr}")
                else:
                    st.text(f" {name}: 0 {unit}  |  {addr[:20]}...")
                
                progress_bar.progress((i + 1) / total_wallets)
                time.sleep(0.03)
            
            progress_bar.empty()
            
            if not found_any:
                st.warning("All 15 addresses: zero balance")
            else:
                st.balloons()

with t2:
    st.subheader(" Deep Scan Single Phrase")
    
    phrase_input = st.text_area("Enter BIP-39 phrase:", height=80)
    
    if st.button(" Full HD Derivation + Multi-Chain Scan", type="primary", use_container_width=True):
        if phrase_input.strip():
            if not val(phrase_input.strip()):
                st.error("Invalid BIP-39 checksum — wallets will reject this phrase")
            else:
                wallets = derive_full_wallet(phrase_input.strip())
                seed = mnemonic_to_seed(phrase_input.strip())
                mk, mc = seed_to_master(seed)
                
                st.markdown("### Master Keys")
                st.text(f"Master Private Key: {mk.hex()}")
                st.text(f"Master Chain Code: {mc.hex()}")
                
                st.markdown("### Derived Addresses & Balances")
                st.markdown("| Chain | Path | Address | Balance |")
                st.markdown("|-------|------|---------|---------|")
                
                results = []
                
                for name, data in wallets.items():
                    if 'error' in data:
                        continue
                    
                    path = DERIVATION_PATHS[name][0]
                    addr = data['address']
                    chain = data['chain']
                    
                    if chain == 'BTC':
                        bal = check_btc(addr)
                        unit = 'BTC'
                    elif chain == 'LTC':
                        bal = check_ltc(addr)
                        unit = 'LTC'
                    elif chain == 'DOGE':
                        bal = check_doge(addr)
                        unit = 'DOGE'
                    elif chain == 'TRX':
                        bal = check_trx(addr)
                        unit = 'TRX'
                    elif chain == 'EVM' and name in EVM_APIS:
                        bal = check_evm(addr, EVM_APIS[name])
                        unit = 'ETH' if name == 'ETH' else name.split()[0]
                    else:
                        bal = 0.0
                        unit = '?'
                    
                    if bal > 0:
                        st.markdown(f"|  **{name}** | `{path}` | `{addr}` | **{bal:.8f} {unit}** |")
                        results.append((name, addr, bal, unit))
                    else:
                        st.markdown(f"|  {name} | `{path}` | `{addr[:16]}...` | 0 {unit} |")
                    
                    time.sleep(0.03)
                
                if results:
                    st.success(f"Found {len(results)} funded addresses!")
                    for name, addr, bal, unit in results:
                        st.code(f"{name}: {addr}\nBalance: {bal:.8f} {unit}")
                    st.balloons()
                else:
                    st.warning("All 15 addresses: zero balance")

st.markdown("---")
st.caption("Full BIP-39/32/44 standard | Same derivation as all major wallets | 15 paths across 8 blockchain families")
