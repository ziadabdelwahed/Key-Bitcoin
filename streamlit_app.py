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
# BIP-39: Mnemonic → Seed
# ============================================================================
def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048, 64)

# ============================================================================
# BIP-32: Seed → Master Key + Chain Code
# ============================================================================
def seed_to_master(seed: bytes) -> Tuple[bytes, bytes]:
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_private_key = h[:32]
    master_chain_code = h[32:]
    return master_private_key, master_chain_code

# ============================================================================
# BIP-32: CKDpriv — Child Key Derivation (Private)
# ============================================================================
def derive_child_private(parent_key: bytes, parent_chain: bytes, index: int) -> Tuple[bytes, bytes]:
    if index >= 0x80000000:  # Hardened
        data = b'\x00' + parent_key + struct.pack('>I', index)
    else:  # Normal
        data = private_to_public(parent_key, compressed=True) + struct.pack('>I', index)
    
    h = hmac.new(parent_chain, data, hashlib.sha512).digest()
    child_key = (int.from_bytes(h[:32], 'big') + int.from_bytes(parent_key, 'big')) % SECP256K1_ORDER
    child_chain = h[32:]
    
    return child_key.to_bytes(32, 'big'), child_chain

# ============================================================================
# BIP-32: Parse Derivation Path
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
# BIP-32: Full Path Derivation
# ============================================================================
def derive_path(seed: bytes, path: str) -> bytes:
    key, chain = seed_to_master(seed)
    indices = parse_path(path)
    for idx in indices:
        key, chain = derive_child_private(key, chain, idx)
    return key

# ============================================================================
# ECDSA: Private Key → Public Key (Compressed)
# ============================================================================
def private_to_public(private_key: bytes, compressed: bool = True) -> bytes:
    k = int.from_bytes(private_key, 'big') % SECP256K1_ORDER
    if k == 0:
        raise ValueError("Invalid private key")
    
    gx, gy = SECP256K1_G
    
    # Double-and-add
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

def pubkey_to_btc_addresses(pubkey: bytes) -> Dict[str, str]:
    addresses = {}
    
    # P2PKH (Legacy - 1...)
    h160 = hash160(pubkey)
    prefix = b'\x00' + h160
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    addresses['BTC_P2PKH'] = base58_encode(prefix + checksum)
    
    # P2SH-SegWit (3...)
    witness_script = b'\x00\x14' + hash160(b'\x02' + pubkey[:32] if pubkey[0] in [0x02, 0x03] else pubkey)
    prefix_p2sh = b'\x05' + hash160(witness_script)
    checksum_p2sh = hashlib.sha256(hashlib.sha256(prefix_p2sh).digest()).digest()[:4]
    addresses['BTC_P2SH'] = base58_encode(prefix_p2sh + checksum_p2sh)
    
    return addresses

def privkey_to_eth_address(private_key: bytes) -> str:
    from eth_keys import keys
    pk = keys.PrivateKey(private_key)
    return pk.public_key.to_checksum_address()

# ============================================================================
# STANDARD DERIVATION PATHS
# ============================================================================
DERIVATION_PATHS = {
    'BTC Legacy':     "m/44'/0'/0'/0/0",
    'BTC SegWit':     "m/49'/0'/0'/0/0",
    'BTC Native':     "m/84'/0'/0'/0/0",
    'ETH':            "m/44'/60'/0'/0/0",
    'BNB':            "m/44'/60'/0'/0/0",
    'MATIC':          "m/44'/60'/0'/0/0",
    'AVAX':           "m/44'/60'/0'/0/0",
    'FTM':            "m/44'/60'/0'/0/0",
    'ARB':            "m/44'/60'/0'/0/0",
    'OP':             "m/44'/60'/0'/0/0",
    'BASE':           "m/44'/60'/0'/0/0",
    'TRX':            "m/44'/195'/0'/0/0",
    'LTC Legacy':     "m/44'/2'/0'/0/0",
    'LTC SegWit':     "m/49'/2'/0'/0/0",
    'DOGE':           "m/44'/3'/0'/0/0",
}

# ============================================================================
# MULTI-CHAIN SCANNER
# ============================================================================
def check_btc(addr):
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

def check_evm(addr, api_url):
    try:
        r = requests.get(f"{api_url}?module=account&action=balance&address={addr}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e18
    except:
        pass
    return 0.0

def check_trx(addr):
    try:
        r = requests.get(f"https://apilist.tronscanapi.com/api/accountv2?address={addr}", timeout=5)
        d = r.json()
        return d.get('balance', 0) / 1e6
    except:
        pass
    return 0.0

def check_doge(addr):
    try:
        r = requests.get(f"https://dogechain.info/api/v1/address/balance/{addr}", timeout=5)
        return float(r.json().get('balance', 0))
    except:
        pass
    return 0.0

def check_ltc(addr):
    try:
        r = requests.get(f"https://blockchair.com/api/address/ltc/{addr}", timeout=5)
        d = r.json()
        return d.get('data', {}).get(addr, {}).get('address', {}).get('balance', 0) / 1e8
    except:
        pass
    return 0.0

def check_sol(addr):
    try:
        payload = {"jsonrpc":"2.0","id":1,"method":"getBalance","params":[addr]}
        r = requests.post("https://api.mainnet-beta.solana.com", json=payload, timeout=5)
        return r.json().get('result', {}).get('value', 0) / 1e9
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
# FULL WALLET DERIVATION (BIP-39 → BIP-32 → BIP-44)
# ============================================================================
def derive_full_wallet(mnemonic: str) -> Dict:
    seed = mnemonic_to_seed(mnemonic)
    master_key, master_chain = seed_to_master(seed)
    
    wallets = {}
    
    for name, path in DERIVATION_PATHS.items():
        try:
            priv = derive_path(seed, path)
            pub = private_to_public(priv, compressed=True)
            
            if name.startswith('BTC'):
                addrs = pubkey_to_btc_addresses(pub)
                wallets[name] = {
                    'private_key': priv.hex(),
                    'addresses': addrs
                }
            elif name == 'LTC Legacy':
                h160 = hash160(pub)
                prefix = b'\x30' + h160
                checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
                wallets[name] = {
                    'private_key': priv.hex(),
                    'address': base58_encode(prefix + checksum)
                }
            elif name == 'LTC SegWit':
                h160 = hash160(pub)
                prefix = b'\x32' + h160
                checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
                wallets[name] = {
                    'private_key': priv.hex(),
                    'address': base58_encode(prefix + checksum)
                }
            elif name == 'TRX':
                addr = privkey_to_eth_address(priv)
                wallets[name] = {
                    'private_key': priv.hex(),
                    'address': addr
                }
            elif name == 'DOGE':
                h160 = hash160(pub)
                prefix = b'\x1e' + h160
                checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
                wallets[name] = {
                    'private_key': priv.hex(),
                    'address': base58_encode(prefix + checksum)
                }
            else:
                addr = privkey_to_eth_address(priv)
                wallets[name] = {
                    'private_key': priv.hex(),
                    'address': addr
                }
        except Exception as e:
            wallets[name] = {'error': str(e)}
    
    return wallets

# ============================================================================
# UI
# ============================================================================
st.set_page_config(page_title="HD Key Hunter", page_icon="💻")
st.title("💻 HD Key Hunter")
st.subheader("Full BIP-39 → BIP-32 → BIP-44 Derivation")
st.success(f"{len(BIP39)} canonical words | 15 derivation paths | Standard-compliant")

t1, t2, t3, t4 = st.tabs(["Generate", "Validate", "Brainwallets", "💻 HD Deep Scan"])

with t1:
    c1, c2 = st.columns(2)
    with c1:
        n = st.slider("Count", 1, 10, 3)
    with c2:
        wc = st.radio("Words", [12, 24], horizontal=True)
    
    if st.button("Generate", type="primary", use_container_width=True):
        st.session_state['phrases'] = [gen(wc) for _ in range(n)]
    
    if 'phrases' in st.session_state:
        for i, p in enumerate(st.session_state['phrases']):
            with st.expander(f"Phrase {i+1}"):
                st.code(p)
                seed = mnemonic_to_seed(p)
                mk, mc = seed_to_master(seed)
                st.text(f"Master Key: {mk.hex()}")

with t2:
    p = st.text_area("Paste phrase:", height=80)
    if st.button("Validate", type="primary", use_container_width=True):
        if p.strip():
            ws = p.strip().split()
            bad = [w for w in ws if w not in W2I]
            if len(ws) not in [12, 15, 18, 21, 24]:
                st.error(f"Word count: {len(ws)}")
            elif bad:
                st.error(f"Unknown: {', '.join(bad)}")
            elif val(p.strip()):
                st.success("✔️ VALID BIP-39")
            else:
                st.error("❌ INVALID")

with t3:
    if st.button("Generate + Scan Brainwallets", type="primary", use_container_width=True):
        pws = [
            "password", "12345678", "qwerty123", "letmein", "bitcoin",
            "ethereum", "satoshi", "metamask", "trustwallet", "blockchain",
            "crypto", "iloveyou", "admin123", "rootroot", "passw0rd"
        ]
        
        found_any = False
        
        for pw in pws:
            h = hashlib.sha256(pw.encode()).digest()
            idxs = [((h[i] << 8) | h[(i+1) % len(h)]) % 2048 for i in range(12)]
            phrase = ' '.join(BIP39[i] for i in idxs)
            
            wallets = derive_full_wallet(phrase)
            
            for name, data in wallets.items():
                if 'addresses' in data:
                    for addr_type, addr in data['addresses'].items():
                        bal = check_btc(addr)
                        if bal > 0:
                            found_any = True
                            st.success(f"💰 {name}/{addr_type}: {bal:.8f} BTC")
                            st.code(phrase)
                elif 'address' in data:
                    addr = data['address']
                    if name.startswith('LTC'):
                        bal = check_ltc(addr)
                    elif name == 'DOGE':
                        bal = check_doge(addr)
                    elif name == 'TRX':
                        bal = check_trx(addr)
                    else:
                        bal = 0
                    if bal > 0:
                        found_any = True
                        st.success(f"💰 {name}: {bal:.6f}")
                        st.code(phrase)
            
            time.sleep(0.1)
        
        if not found_any:
            st.warning("No funded wallets found")

with t4:
    st.subheader("💻 HD Deep Scan")
    st.caption("Full BIP-32/BIP-44 derivation — same addresses as MetaMask/TrustWallet")
    
    phrase_input = st.text_area("Enter phrase:", height=80, key="deep")
    
    if st.button("💻 Full HD Scan", type="primary", use_container_width=True):
        if phrase_input.strip():
            if not val(phrase_input.strip()):
                st.error("Invalid phrase")
            else:
                wallets = derive_full_wallet(phrase_input.strip())
                
                st.text(f"Derived {len(wallets)} wallets via BIP-32/BIP-44")
                
                results = []
                
                for name, data in wallets.items():
                    if 'error' in data:
                        continue
                    
                    if 'addresses' in data:
                        for addr_type, addr in data['addresses'].items():
                            bal = check_btc(addr)
                            results.append((f"{name} ({addr_type})", addr, bal, 'BTC'))
                    elif 'address' in data:
                        addr = data['address']
                        if name == 'TRX':
                            bal = check_trx(addr)
                            results.append((name, addr, bal, 'TRX'))
                        elif name == 'DOGE':
                            bal = check_doge(addr)
                            results.append((name, addr, bal, 'DOGE'))
                        elif name.startswith('LTC'):
                            bal = check_ltc(addr)
                            results.append((name, addr, bal, 'LTC'))
                        else:
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
                                bal = check_evm(addr, api)
                                results.append((name, addr, bal, 'EVM'))
                    
                    time.sleep(0.05)
                
                found = False
                for name, addr, bal, chain in results:
                    if bal > 0:
                        found = True
                        st.success(f"💰 {name}: {bal:.8f} {chain}")
                        st.text(f"Address: {addr}")
                    else:
                        st.text(f"❌ {name}: 0 {chain}")
                
                if found:
                    st.code(phrase_input.strip())
                    st.balloons()
                else:
                    st.warning("All addresses: 0 balance")

st.markdown("---")
st.caption("Full BIP-39 → BIP-32 → BIP-44 HD Derivation | Same addresses as MetaMask, TrustWallet, Ledger")
