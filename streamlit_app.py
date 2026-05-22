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
# BIP-39
# ============================================================================
def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048, 64)

# ============================================================================
# BIP-32
# ============================================================================
def seed_to_master(seed: bytes) -> Tuple[bytes, bytes]:
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return h[:32], h[32:]

def derive_child_private(parent_key: bytes, parent_chain: bytes, index: int) -> Tuple[bytes, bytes]:
    if index >= 0x80000000:
        data = b'\x00' + parent_key + struct.pack('>I', index)
    else:
        data = private_to_public(parent_key, compressed=True) + struct.pack('>I', index)
    
    h = hmac.new(parent_chain, data, hashlib.sha512).digest()
    child_key = (int.from_bytes(h[:32], 'big') + int.from_bytes(parent_key, 'big')) % SECP256K1_ORDER
    child_chain = h[32:]
    return child_key.to_bytes(32, 'big'), child_chain

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

def derive_path(seed: bytes, path: str) -> bytes:
    key, chain = seed_to_master(seed)
    indices = parse_path(path)
    for idx in indices:
        key, chain = derive_child_private(key, chain, idx)
    return key

# ============================================================================
# ECDSA
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
        prefix = 0x02 if ry % 2 == 0 else 0x03
        return bytes([prefix]) + rx.to_bytes(32, 'big')
    else:
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
        if y1 != y2:
            return (0, 0)
        return point_double(x1, y1)
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

def btc_p2pkh(pubkey: bytes) -> str:
    h = hash160(pubkey)
    prefix = b'\x00' + h
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58_encode(prefix + checksum)

def btc_p2sh(pubkey: bytes) -> str:
    h = hash160(pubkey)
    witness = b'\x00\x14' + h
    prefix = b'\x05' + hash160(witness)
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58_encode(prefix + checksum)

def eth_addr(private_key: bytes) -> str:
    pub = private_to_public(private_key, compressed=False)
    h = hashlib.sha256(pub[1:]).digest()
    addr_bytes = h[-20:]
    addr_hex = addr_bytes.hex()
    cs_input = hashlib.sha256(addr_hex.encode()).hexdigest()
    result = '0x'
    for i, char in enumerate(addr_hex):
        if int(cs_input[i], 16) >= 8:
            result += char.upper()
        else:
            result += char.lower()
    return result

def ltc_p2pkh(pubkey: bytes) -> str:
    h = hash160(pubkey)
    prefix = b'\x30' + h
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58_encode(prefix + checksum)

def ltc_p2sh(pubkey: bytes) -> str:
    h = hash160(pubkey)
    witness = b'\x00\x14' + h
    prefix = b'\x32' + hash160(witness)
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58_encode(prefix + checksum)

def doge_addr(pubkey: bytes) -> str:
    h = hash160(pubkey)
    prefix = b'\x1e' + h
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58_encode(prefix + checksum)

# ============================================================================
# DERIVATION PATHS
# ============================================================================
DERIVATION_PATHS = {
    'BTC':  ("m/44'/0'/0'/0/0", 'BTC'),
    'ETH':  ("m/44'/60'/0'/0/0", 'EVM'),
    'BNB':  ("m/44'/60'/0'/0/0", 'EVM'),
    'MATIC':("m/44'/60'/0'/0/0", 'EVM'),
    'AVAX': ("m/44'/60'/0'/0/0", 'EVM'),
    'FTM':  ("m/44'/60'/0'/0/0", 'EVM'),
    'ARB':  ("m/44'/60'/0'/0/0", 'EVM'),
    'OP':   ("m/44'/60'/0'/0/0", 'EVM'),
    'BASE': ("m/44'/60'/0'/0/0", 'EVM'),
    'TRX':  ("m/44'/195'/0'/0/0", 'EVM'),
    'LTC':  ("m/44'/2'/0'/0/0", 'LTC'),
    'DOGE': ("m/44'/3'/0'/0/0", 'DOGE'),
}

# ============================================================================
# TOKEN CONTRACTS
# ============================================================================
USDT_CONTRACTS = {
    'ETH':   '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    'BNB':   '0x55d398326f99059fF775485246999027B3197955',
    'MATIC': '0xc2132D05D31c914a87C6611C10748AEb04B58e8F',
    'AVAX':  '0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7',
    'ARB':   '0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9',
    'OP':    '0x94b008aA00579c1307B0EF2c499aD98a8ce58e58',
    'BASE':  '0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2',
}

# ============================================================================
# SCANNERS
# ============================================================================
def scan_btc(addr):
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

def scan_evm(addr, api_url):
    try:
        r = requests.get(f"{api_url}?module=account&action=balance&address={addr}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e18
    except:
        pass
    return 0.0

def scan_token(addr, contract, api_url):
    try:
        r = requests.get(f"{api_url}?module=account&action=tokenbalance&contractaddress={contract}&address={addr}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e6
    except:
        pass
    return 0.0

def scan_trx(addr):
    try:
        r = requests.get(f"https://apilist.tronscanapi.com/api/accountv2?address={addr}", timeout=5)
        d = r.json()
        return d.get('balance', 0) / 1e6
    except:
        pass
    return 0.0

def scan_doge(addr):
    try:
        r = requests.get(f"https://dogechain.info/api/v1/address/balance/{addr}", timeout=5)
        return float(r.json().get('balance', 0))
    except:
        pass
    return 0.0

def scan_ltc(addr):
    try:
        r = requests.get(f"https://api.blockcypher.com/v1/ltc/main/addrs/{addr}/balance", timeout=5)
        return r.json().get('final_balance', 0) / 1e8
    except:
        pass
    return 0.0

def scan_sol(addr):
    try:
        payload = {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [addr]}
        r = requests.post("https://api.mainnet-beta.solana.com", json=payload, timeout=5)
        return r.json().get('result', {}).get('value', 0) / 1e9
    except:
        pass
    return 0.0

def scan_sol_usdt(addr):
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountsByOwner",
            "params": [
                addr,
                {"mint": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"},
                {"encoding": "jsonParsed"}
            ]
        }
        r = requests.post("https://api.mainnet-beta.solana.com", json=payload, timeout=5)
        data = r.json()
        accounts = data.get('result', {}).get('value', [])
        total = 0
        for acc in accounts:
            info = acc.get('account', {}).get('data', {}).get('parsed', {}).get('info', {})
            token_amount = info.get('tokenAmount', {})
            total += float(token_amount.get('uiAmount', 0))
        return total
    except:
        pass
    return 0.0

# ============================================================================
# BIP-39 GENERATOR
# ============================================================================
def gen(wc=12):
    ENT = {12: 128, 24: 256}[wc]
    CS = ENT // 32
    e = secrets.token_bytes(ENT // 8)
    h = hashlib.sha256(e).digest()
    c = h[0] >> (8 - CS)
    ei = int.from_bytes(e, 'big')
    comb = (ei << CS) | c
    words = []
    for i in range(wc):
        shift = (ENT + CS) - 11 * (i + 1)
        words.append(BIP39[(comb >> shift) & 0x7FF])
    return ' '.join(words)

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
# SOLANA KEYPAIR DERIVATION
# ============================================================================
def derive_solana_keypair(seed: bytes) -> Tuple[str, str]:
    path = "m/44'/501'/0'/0'"
    priv = derive_path(seed, path)
    pub_bytes = private_to_public(priv, compressed=False)
    pub_hex = hashlib.sha256(pub_bytes).digest().hex()[:64]
    return priv.hex(), pub_hex

# ============================================================================
# UI
# ============================================================================
st.set_page_config(page_title="Key Hunter", page_icon="K")
st.title("Key Hunter")
st.subheader("Multi-Chain Balance Scanner")
st.caption(f"{len(BIP39)} BIP-39 words | 14 Assets: BTC ETH BNB MATIC AVAX FTM ARB OP BASE TRX LTC DOGE SOL + USDT")

tab1, tab2 = st.tabs(["Scan Single Phrase", "Generate & Scan"])

with tab1:
    phrase = st.text_area("Enter BIP-39 mnemonic:", height=80)
    
    if st.button("Scan All Chains", type="primary", use_container_width=True):
        if phrase.strip():
            if not val(phrase.strip()):
                st.error("Invalid checksum")
            else:
                seed = mnemonic_to_seed(phrase.strip())
                mk, mc = seed_to_master(seed)
                
                st.markdown("---")
                st.markdown("### Results")
                
                results = []
                
                for name, (path, typ) in DERIVATION_PATHS.items():
                    priv = derive_path(seed, path)
                    pub = private_to_public(priv, compressed=True)
                    
                    if typ == 'BTC':
                        addr = btc_p2pkh(pub)
                        bal = scan_btc(addr)
                        results.append((name, f"{bal:.8f}", "BTC"))
                    
                    elif typ == 'LTC':
                        addr = ltc_p2pkh(pub)
                        bal = scan_ltc(addr)
                        results.append((name, f"{bal:.8f}", "LTC"))
                    
                    elif typ == 'DOGE':
                        addr = doge_addr(pub)
                        bal = scan_doge(addr)
                        results.append((name, f"{bal:.8f}", "DOGE"))
                    
                    elif name == 'TRX':
                        addr = eth_addr(priv)
                        bal = scan_trx(addr)
                        results.append((name, f"{bal:.6f}", "TRX"))
                    
                    elif typ == 'EVM':
                        addr = eth_addr(priv)
                        apis = {
                            'ETH': 'https://api.etherscan.io/api',
                            'BNB': 'https://api.bscscan.com/api',
                            'MATIC': 'https://api.polygonscan.com/api',
                            'AVAX': 'https://api.snowtrace.io/api',
                            'FTM': 'https://api.ftmscan.com/api',
                            'ARB': 'https://api.arbiscan.io/api',
                            'OP': 'https://api-optimistic.etherscan.io/api',
                            'BASE': 'https://api.basescan.org/api',
                        }
                        api = apis.get(name)
                        if api:
                            bal = scan_evm(addr, api)
                            results.append((name, f"{bal:.8f}", name))
                            
                            if name in USDT_CONTRACTS:
                                usdt_bal = scan_token(addr, USDT_CONTRACTS[name], api)
                                if usdt_bal > 0:
                                    results.append((f"{name} USDT", f"{usdt_bal:.6f}", "USDT"))
                    
                    time.sleep(0.03)
                
                # Solana
                sol_priv, sol_pub = derive_solana_keypair(seed)
                sol_bal = scan_sol(sol_pub)
                results.append(("SOL", f"{sol_bal:.6f}", "SOL"))
                
                sol_usdt = scan_sol_usdt(sol_pub)
                if sol_usdt > 0:
                    results.append(("SOL USDT", f"{sol_usdt:.6f}", "USDT"))
                
                # Display
                col1, col2 = st.columns(2)
                
                for i, (chain, balance, symbol) in enumerate(results):
                    if i % 2 == 0:
                        with col1:
                            if float(balance) > 0:
                                st.success(f"{chain}: {balance} {symbol}")
                            else:
                                st.text(f"{chain}: {balance} {symbol}")
                    else:
                        with col2:
                            if float(balance) > 0:
                                st.success(f"{chain}: {balance} {symbol}")
                            else:
                                st.text(f"{chain}: {balance} {symbol}")
                
                # Total summary
                found = [r for r in results if float(r[1]) > 0]
                if found:
                    st.markdown("---")
                    st.success(f"Found {len(found)} assets with balance")
                    st.code(phrase.strip())
                    st.balloons()
                else:
                    st.markdown("---")
                    st.warning("All 0")

with tab2:
    c1, c2 = st.columns(2)
    with c1:
        n = st.slider("Phrases", 1, 5, 1)
    with c2:
        wc = st.radio("Words", [12, 24], horizontal=True)
    
    if st.button("Generate & Scan", type="primary", use_container_width=True):
        for _ in range(n):
            phrase = gen(wc)
            st.markdown("---")
            st.code(phrase)
            
            seed = mnemonic_to_seed(phrase)
            
            results = []
            
            for name, (path, typ) in DERIVATION_PATHS.items():
                priv = derive_path(seed, path)
                pub = private_to_public(priv, compressed=True)
                
                if typ == 'BTC':
                    addr = btc_p2pkh(pub)
                    bal = scan_btc(addr)
                    results.append((name, bal, "BTC"))
                elif typ == 'LTC':
                    addr = ltc_p2pkh(pub)
                    bal = scan_ltc(addr)
                    results.append((name, bal, "LTC"))
                elif typ == 'DOGE':
                    addr = doge_addr(pub)
                    bal = scan_doge(addr)
                    results.append((name, bal, "DOGE"))
                elif name == 'TRX':
                    addr = eth_addr(priv)
                    bal = scan_trx(addr)
                    results.append((name, bal, "TRX"))
                elif typ == 'EVM':
                    addr = eth_addr(priv)
                    apis = {
                        'ETH': 'https://api.etherscan.io/api',
                        'BNB': 'https://api.bscscan.com/api',
                        'MATIC': 'https://api.polygonscan.com/api',
                        'AVAX': 'https://api.snowtrace.io/api',
                        'FTM': 'https://api.ftmscan.com/api',
                        'ARB': 'https://api.arbiscan.io/api',
                        'OP': 'https://api-optimistic.etherscan.io/api',
                        'BASE': 'https://api.basescan.org/api',
                    }
                    api = apis.get(name)
                    if api:
                        bal = scan_evm(addr, api)
                        results.append((name, bal, name))
                        if name in USDT_CONTRACTS:
                            usdt_bal = scan_token(addr, USDT_CONTRACTS[name], api)
                            if usdt_bal > 0:
                                results.append((f"{name} USDT", usdt_bal, "USDT"))
                
                time.sleep(0.02)
            
            # Solana
            sol_priv, sol_pub = derive_solana_keypair(seed)
            sol_bal = scan_sol(sol_pub)
            results.append(("SOL", sol_bal, "SOL"))
            sol_usdt = scan_sol_usdt(sol_pub)
            if sol_usdt > 0:
                results.append(("SOL USDT", sol_usdt, "USDT"))
            
            # Display compact
            found_any = False
            for name, bal, sym in results:
                if bal > 0:
                    found_any = True
                    st.success(f"{name}: {bal:.6f} {sym}")
                else:
                    st.text(f"{name}: 0.000 {sym}")
            
            if found_any:
                st.code(phrase)
                st.balloons()
            else:
                st.warning("All zero")

st.markdown("---")
st.caption("BTC | ETH | BNB | MATIC | AVAX | FTM | ARB | OP | BASE | TRX | LTC | DOGE | SOL | USDT")
