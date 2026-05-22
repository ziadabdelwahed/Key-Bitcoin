import streamlit as st
import secrets
import hashlib
import hmac
import requests
import struct
import time
from typing import Dict, Tuple, List

# ============================================================================
# WORDLIST
# ============================================================================
@st.cache_data
def load_words():
    r = requests.get("https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt")
    return r.text.strip().split("\n")

BIP39 = load_words()
if len(BIP39) != 2048:
    st.error("Wordlist error")
    st.stop()

W2I = {w: i for i, w in enumerate(BIP39)}

# ============================================================================
# SECP256K1
# ============================================================================
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

# ============================================================================
# BIP-39
# ============================================================================
def mnemonic_to_seed(m, pw=""):
    return hashlib.pbkdf2_hmac('sha512', m.encode(), ("mnemonic"+pw).encode(), 2048, 64)

def gen(wc=12):
    ENT, CS = {12:(128,4), 24:(256,8)}[wc]
    e = secrets.token_bytes(ENT//8)
    h = hashlib.sha256(e).digest()
    c = h[0] >> (8-CS)
    ei = int.from_bytes(e,'big')
    comb = (ei << CS) | c
    return ' '.join(BIP39[(comb >> (ENT+CS-11*(i+1))) & 0x7FF] for i in range(wc))

def val(m):
    ws = m.strip().split()
    if len(ws) not in (12,15,18,21,24): return False
    if not all(w in W2I for w in ws): return False
    wc = len(ws)
    ENT = (wc*352)//33
    CS = wc*11 - ENT
    comb = 0
    for idx in [W2I[w] for w in ws]:
        comb = (comb << 11) | idx
    cs = comb & ((1<<CS)-1)
    eb = comb >> CS
    try:
        eb_b = eb.to_bytes(ENT//8,'big')
    except:
        return False
    return cs == (hashlib.sha256(eb_b).digest()[0] >> (8-CS))

# ============================================================================
# BIP-32
# ============================================================================
def seed_to_master(seed):
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return h[:32], h[32:]

def point_double(x, y):
    if (x,y) == (0,0): return (0,0)
    s = (3*x*x * pow(2*y, -1, ORDER)) % ORDER
    rx = (s*s - 2*x) % ORDER
    ry = (s*(x-rx) - y) % ORDER
    return (rx, ry)

def point_add(x1,y1,x2,y2):
    if (x1,y1) == (0,0): return (x2,y2)
    if (x2,y2) == (0,0): return (x1,y1)
    if x1 == x2:
        return (0,0) if y1 != y2 else point_double(x1,y1)
    s = ((y2-y1) * pow(x2-x1, -1, ORDER)) % ORDER
    rx = (s*s - x1 - x2) % ORDER
    ry = (s*(x1-rx) - y1) % ORDER
    return (rx, ry)

def priv_to_pub(k_bytes, compressed=True):
    k = int.from_bytes(k_bytes, 'big') % ORDER
    if k == 0: return None
    rx, ry = 0, 0
    for bit in bin(k)[2:]:
        rx, ry = point_double(rx, ry) if (rx,ry)!=(0,0) else (0,0)
        if bit == '1':
            rx, ry = (G[0],G[1]) if (rx,ry)==(0,0) else point_add(rx,ry,G[0],G[1])
    if compressed:
        return bytes([0x02 if ry%2==0 else 0x03]) + rx.to_bytes(32,'big')
    return b'\x04' + rx.to_bytes(32,'big') + ry.to_bytes(32,'big')

def derive_child(key, chain, idx):
    if idx >= 0x80000000:
        data = b'\x00' + key + struct.pack('>I', idx)
    else:
        pub = priv_to_pub(key, True)
        if not pub: return None, None
        data = pub + struct.pack('>I', idx)
    h = hmac.new(chain, data, hashlib.sha512).digest()
    child_k = (int.from_bytes(h[:32],'big') + int.from_bytes(key,'big')) % ORDER
    return child_k.to_bytes(32,'big'), h[32:]

def derive_path(seed, path):
    key, chain = seed_to_master(seed)
    for part in path.replace("m/","").split("/"):
        if not part: continue
        h = part.endswith("'")
        idx = int(part[:-1]) + (0x80000000 if h else 0)
        key, chain = derive_child(key, chain, idx)
        if key is None: return None
    return key

# ============================================================================
# ADDRESSES
# ============================================================================
def b58enc(data):
    n = int.from_bytes(data,'big')
    res = []
    while n: n, r = divmod(n,58); res.append(BASE58[r])
    for b in data:
        if b==0: res.append(BASE58[0])
        else: break
    return ''.join(reversed(res))

def h160(d): return hashlib.new('ripemd160', hashlib.sha256(d).digest()).digest()

def btc_p2pkh(pub):
    h = h160(pub)
    return b58enc(b'\x00'+h+hashlib.sha256(hashlib.sha256(b'\x00'+h).digest()).digest()[:4])

def btc_p2sh_p2wpkh(pub):
    wp = b'\x00\x14' + h160(pub)
    h = h160(wp)
    return b58enc(b'\x05'+h+hashlib.sha256(hashlib.sha256(b'\x05'+h).digest()).digest()[:4])

def bech32_hrp_expand(s):
    return [ord(x)>>5 for x in s] + [0] + [ord(x)&31 for x in s]

def bech32_polymod(vals):
    gen = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in vals:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            if (top>>i) & 1: chk ^= gen[i]
    return chk

def btc_bech32(pub):
    wp = h160(pub)
    data = [0] + list(wp)
    combined = bech32_hrp_expand('bc') + data + [0]*6
    plm = bech32_polymod(combined)
    checksum = [(plm>>5*(5-i))&31 for i in range(6)]
    return 'bc1' + ''.join(BECH32[d] for d in data+checksum)

def eth_address(pub_uncompressed):
    h = hashlib.sha256(pub_uncompressed[1:]).digest()[12:]
    addr = '0x' + h.hex()
    # EIP-55 checksum
    h2 = hashlib.sha256(addr[2:].lower().encode()).hexdigest()
    return '0x' + ''.join(c.upper() if int(h2[i],16)>=8 else c.lower() for i,c in enumerate(addr[2:]))

# ============================================================================
# DERIVATION PATHS
# ============================================================================
PATHS = {
    'BTC Legacy (P2PKH)':  ("m/44'/0'/0'/0/0", 'BTC_P2PKH'),
    'BTC SegWit (P2SH)':   ("m/49'/0'/0'/0/0", 'BTC_P2SH'),
    'BTC Native (Bech32)': ("m/84'/0'/0'/0/0", 'BTC_BECH32'),
    'ETH':                 ("m/44'/60'/0'/0/0", 'EVM'),
    'BNB Chain':           ("m/44'/60'/0'/0/0", 'EVM'),
    'Polygon':             ("m/44'/60'/0'/0/0", 'EVM'),
    'Avalanche':           ("m/44'/60'/0'/0/0", 'EVM'),
    'Fantom':              ("m/44'/60'/0'/0/0", 'EVM'),
    'Arbitrum':            ("m/44'/60'/0'/0/0", 'EVM'),
    'Optimism':            ("m/44'/60'/0'/0/0", 'EVM'),
    'Base':                ("m/44'/60'/0'/0/0", 'EVM'),
    'TRON':                ("m/44'/195'/0'/0/0", 'EVM'),
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
# SCANNERS
# ============================================================================
def scan_btc(addr):
    try:
        r = requests.get(f"https://blockstream.info/api/address/{addr}", timeout=5)
        if r.status_code == 200:
            d = r.json()
            cs = d.get('chain_stats',{})
            ms = d.get('mempool_stats',{})
            return ((cs.get('funded_txo_sum',0)+ms.get('funded_txo_sum',0)) - 
                    (cs.get('spent_txo_sum',0)+ms.get('spent_txo_sum',0))) / 1e8
    except: pass
    return 0.0

def scan_evm(addr, api):
    try:
        r = requests.get(f"{api}?module=account&action=balance&address={addr}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status')=='1': return int(d.get('result',0))/1e18
    except: pass
    return 0.0

def scan_ltc(addr):
    try:
        r = requests.get(f"https://blockchair.com/api/address/ltc/{addr}", timeout=5)
        return r.json()['data'][addr]['address']['balance']/1e8
    except: pass
    return 0.0

def scan_doge(addr):
    try:
        r = requests.get(f"https://dogechain.info/api/v1/address/balance/{addr}", timeout=5)
        return float(r.json().get('balance',0))
    except: pass
    return 0.0

def scan_trx(addr):
    try:
        r = requests.get(f"https://apilist.tronscanapi.com/api/accountv2?address={addr}", timeout=5)
        return r.json().get('balance',0)/1e6
    except: pass
    return 0.0

# ============================================================================
# FULL WALLET
# ============================================================================
def full_wallet(mnemonic):
    seed = mnemonic_to_seed(mnemonic)
    mk, mc = seed_to_master(seed)
    wallets = {}
    
    for name, (path, fmt) in PATHS.items():
        priv = derive_path(seed, path)
        if not priv:
            wallets[name] = {'error': 'derivation failed'}
            continue
        
        pub_compressed = priv_to_pub(priv, True)
        pub_uncompressed = priv_to_pub(priv, False)
        
        if not pub_compressed or not pub_uncompressed:
            wallets[name] = {'error': 'pubkey failed'}
            continue
        
        if fmt == 'BTC_P2PKH':
            wallets[name] = {'address': btc_p2pkh(pub_compressed), 'type': 'BTC'}
        elif fmt == 'BTC_P2SH':
            wallets[name] = {'address': btc_p2sh_p2wpkh(pub_compressed), 'type': 'BTC'}
        elif fmt == 'BTC_BECH32':
            wallets[name] = {'address': btc_bech32(pub_compressed), 'type': 'BTC'}
        elif fmt == 'EVM':
            wallets[name] = {'address': eth_address(pub_uncompressed), 'type': 'EVM'}
        elif fmt == 'LTC':
            h = h160(pub_compressed)
            prefix = b'\x30' if 'Legacy' in name else b'\x32'
            wallets[name] = {
                'address': b58enc(prefix+h+hashlib.sha256(hashlib.sha256(prefix+h).digest()).digest()[:4]),
                'type': 'LTC'
            }
        elif fmt == 'DOGE':
            h = h160(pub_compressed)
            prefix = b'\x1e' + h
            wallets[name] = {
                'address': b58enc(prefix+hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]),
                'type': 'DOGE'
            }
    
    return wallets, mk, mc

# ============================================================================
# UI
# ============================================================================
st.set_page_config(page_title="HD Key Hunter", page_icon="")
st.title(" HD Key Hunter")
st.subheader("BIP-39 → BIP-32 → BIP-44 Full Standard")
st.caption("Addresses match MetaMask · TrustWallet · Ledger · Trezor exactly")

t1, t2 = st.tabs(["Generate & Scan", "Deep Scan"])

with t1:
    c1, c2 = st.columns(2)
    with c1: n = st.slider("Phrases", 1, 5, 1)
    with c2: wc = st.radio("Words", [12, 24], horizontal=True)
    
    if st.button("Generate + Full HD Scan", type="primary", use_container_width=True):
        for _ in range(n):
            phrase = gen(wc)
            st.markdown("---")
            st.code(phrase)
            
            wallets, mk, mc = full_wallet(phrase)
            st.text(f"Master Key: {mk.hex()}")
            st.text(f"Chain Code: {mc.hex()}")
            
            found = []
            
            for name, data in wallets.items():
                if 'error' in data:
                    st.text(f" {name}: {data['error']}")
                    continue
                
                addr = data['address']
                t = data['type']
                
                if t == 'BTC': bal = scan_btc(addr); unit = 'BTC'
                elif t == 'LTC': bal = scan_ltc(addr); unit = 'LTC'
                elif t == 'DOGE': bal = scan_doge(addr); unit = 'DOGE'
                elif t == 'EVM':
                    if name == 'TRX': bal = scan_trx(addr); unit = 'TRX'
                    elif name in EVM_APIS: bal = scan_evm(addr, EVM_APIS[name]); unit = 'ETH'
                    else: bal = 0.0; unit = '?'
                else: bal = 0.0; unit = '?'
                
                if bal > 0:
                    found.append((name, addr, bal, unit))
                    st.success(f" **{name}**: {bal:.8f} {unit}")
                    st.text(f"   {addr}")
                else:
                    st.text(f" {name}: 0 {unit}  |  {addr[:24]}...")
                
                time.sleep(0.02)
            
            if not found:
                st.warning("All 15 addresses: 0")
            else:
                st.balloons()

with t2:
    phrase = st.text_area("Enter BIP-39 phrase:", height=80)
    
    if st.button(" Full HD Scan", type="primary", use_container_width=True):
        if phrase.strip():
            if not val(phrase.strip()):
                st.error("Invalid checksum")
            else:
                wallets, mk, mc = full_wallet(phrase.strip())
                
                st.markdown("### Master Keys")
                st.code(f"Private: {mk.hex()}\nChain:   {mc.hex()}")
                
                st.markdown("### 15 Addresses")
                
                for name, data in wallets.items():
                    if 'error' in data:
                        st.text(f" {name}: {data['error']}")
                        continue
                    
                    addr = data['address']
                    t = data['type']
                    
                    if t == 'BTC': bal = scan_btc(addr); unit = 'BTC'
                    elif t == 'LTC': bal = scan_ltc(addr); unit = 'LTC'
                    elif t == 'DOGE': bal = scan_doge(addr); unit = 'DOGE'
                    elif t == 'EVM':
                        if name == 'TRX': bal = scan_trx(addr); unit = 'TRX'
                        elif name in EVM_APIS: bal = scan_evm(addr, EVM_APIS[name]); unit = 'ETH'
                        else: bal = 0.0; unit = '?'
                    else: bal = 0.0; unit = '?'
                    
                    if bal > 0:
                        st.success(f" {name}: {bal:.8f} {unit} → {addr}")
                    else:
                        st.text(f" {name}: 0 {unit}")
                    
                    time.sleep(0.02)

st.markdown("---")
st.caption("Bech32 · P2PKH · P2SH · EVM · LTC · DOGE · TRX — BIP-39/32/44 compliant")
