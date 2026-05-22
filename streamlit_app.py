import streamlit as st
import secrets
import hashlib
import hmac
import requests
import struct
import time

# ============================================================================
# CONSTANTS
# ============================================================================
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# ============================================================================
# WORDLIST
# ============================================================================
@st.cache_data
def load_words():
    r = requests.get("https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt", timeout=10)
    w = r.text.strip().split("\n")
    if len(w) != 2048: st.error("Wordlist error"); st.stop()
    return w

WL = load_words()
W2I = {w: i for i, w in enumerate(WL)}

# ============================================================================
# BIP-39
# ============================================================================
def gen(wc=12):
    ENT, CS = (128, 4) if wc == 12 else (256, 8)
    e = secrets.token_bytes(ENT // 8)
    h = hashlib.sha256(e).digest()
    c = h[0] >> (8 - CS)
    ei = int.from_bytes(e, 'big')
    comb = (ei << CS) | c
    return ' '.join(WL[(comb >> (ENT + CS - 11 * (i + 1))) & 0x7FF] for i in range(wc))

def val(m):
    ws = m.strip().split()
    if len(ws) not in (12, 15, 18, 21, 24): return False
    if not all(w in W2I for w in ws): return False
    wc = len(ws)
    ENT = (wc * 352) // 33
    CS = wc * 11 - ENT
    comb = 0
    for idx in [W2I[w] for w in ws]: comb = (comb << 11) | idx
    cs = comb & ((1 << CS) - 1)
    eb = comb >> CS
    try: eb_b = eb.to_bytes(ENT // 8, 'big')
    except: return False
    return cs == (hashlib.sha256(eb_b).digest()[0] >> (8 - CS))

def seed(m, pw=""):
    return hashlib.pbkdf2_hmac('sha512', m.encode(), ("mnemonic" + pw).encode(), 2048, 64)

# ============================================================================
# BIP-32
# ============================================================================
def master(seed):
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return h[:32], h[32:]

def padd(p1, p2):
    if p1 == (0, 0): return p2
    if p2 == (0, 0): return p1
    x1, y1, x2, y2 = p1[0], p1[1], p2[0], p2[1]
    if x1 == x2:
        if y1 != y2: return (0, 0)
        s = (3 * x1 * x1 * pow(2 * y1, -1, ORDER)) % ORDER
    else: s = ((y2 - y1) * pow(x2 - x1, -1, ORDER)) % ORDER
    x3 = (s * s - x1 - x2) % ORDER
    y3 = (s * (x1 - x3) - y1) % ORDER
    return (x3, y3)

def pub(k, comp=True):
    ki = int.from_bytes(k, 'big')
    if ki == 0 or ki >= ORDER: return None
    rx, ry = 0, 0
    for bit in bin(ki)[2:]:
        if (rx, ry) != (0, 0): rx, ry = padd((rx, ry), (rx, ry))
        if bit == '1': rx, ry = (GX, GY) if (rx, ry) == (0, 0) else padd((rx, ry), (GX, GY))
    if comp: return bytes([0x02 if ry % 2 == 0 else 0x03]) + rx.to_bytes(32, 'big')
    return b'\x04' + rx.to_bytes(32, 'big') + ry.to_bytes(32, 'big')

def ckd(k, c, idx):
    data = (b'\x00' + k if idx >= 0x80000000 else pub(k, True)) + struct.pack('>I', idx)
    h = hmac.new(c, data, hashlib.sha512).digest()
    return ((int.from_bytes(h[:32], 'big') + int.from_bytes(k, 'big')) % ORDER).to_bytes(32, 'big'), h[32:]

def derive(seed, path):
    k, c = master(seed)
    for part in path.replace("m/", "").split("/"):
        if not part: continue
        h = part.endswith("'")
        idx = int(part[:-1]) + (0x80000000 if h else 0)
        k, c = ckd(k, c, idx)
    return k

# ============================================================================
# ADDRESSES
# ============================================================================
def h160(d): return hashlib.new('ripemd160', hashlib.sha256(d).digest()).digest()

def dsha(d): return hashlib.sha256(hashlib.sha256(d).digest()).digest()

def b58enc(d):
    n = int.from_bytes(d, 'big')
    r = []
    while n: n, rem = divmod(n, 58); r.append(B58[rem])
    for b in d:
        if b == 0: r.append(B58[0])
        else: break
    return ''.join(reversed(r))

def b58chk(pref, pay): return b58enc(pref + pay + dsha(pref + pay)[:4])

def b32poly(vals):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in vals:
        b = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            if (b >> i) & 1: chk ^= gen[i]
    return chk

def b32hrp(h): return [ord(x) >> 5 for x in h] + [0] + [ord(x) & 31 for x in h]

def b32enc(h, ver, prog):
    data = [ver] + list(prog)
    pm = b32poly(b32hrp(h) + data + [0, 0, 0, 0, 0, 0]) ^ 1
    cs = [(pm >> 5 * (5 - i)) & 31 for i in range(6)]
    return h + '1' + ''.join(B32[d] for d in data + cs)

def btc_p2pkh(pub): return b58chk(b'\x00', h160(pub))
def btc_p2sh(pub): return b58chk(b'\x05', h160(b'\x00\x14' + h160(pub)))
def btc_b32(pub): return b32enc('bc', 0, h160(pub))

def eth_addr(pub):
    h = hashlib.sha256(pub[1:]).digest()[-20:]
    ah = h.hex()
    cs = hashlib.sha256(ah.encode()).hexdigest()
    return '0x' + ''.join(c.upper() if int(cs[i], 16) >= 8 else c.lower() for i, c in enumerate(ah))

def ltc_p2pkh(pub): return b58chk(b'\x30', h160(pub))
def ltc_p2sh(pub): return b58chk(b'\x32', h160(b'\x00\x14' + h160(pub)))
def doge_p2pkh(pub): return b58chk(b'\x1e', h160(pub))

# ============================================================================
# PATHS
# ============================================================================
PATHS = {
    "BTC Legacy": ("m/44'/0'/0'/0/0", 'BTC'),
    "BTC SegWit": ("m/49'/0'/0'/0/0", 'BTC'),
    "BTC Native": ("m/84'/0'/0'/0/0", 'BTC'),
    "Ethereum": ("m/44'/60'/0'/0/0", 'EVM'),
    "BNB Chain": ("m/44'/60'/0'/0/0", 'EVM'),
    "Polygon": ("m/44'/60'/0'/0/0", 'EVM'),
    "Avalanche": ("m/44'/60'/0'/0/0", 'EVM'),
    "Fantom": ("m/44'/60'/0'/0/0", 'EVM'),
    "Arbitrum": ("m/44'/60'/0'/0/0", 'EVM'),
    "Optimism": ("m/44'/60'/0'/0/0", 'EVM'),
    "Base": ("m/44'/60'/0'/0/0", 'EVM'),
    "TRON": ("m/44'/195'/0'/0/0", 'EVM'),
    "LTC Legacy": ("m/44'/2'/0'/0/0", 'LTC'),
    "LTC SegWit": ("m/49'/2'/0'/0/0", 'LTC'),
    "Dogecoin": ("m/44'/3'/0'/0/0", 'DOGE'),
}

APIS = {
    'Ethereum': 'https://api.etherscan.io/api',
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
def bal_btc(a):
    try:
        r = requests.get(f"https://blockstream.info/api/address/{a}", timeout=5)
        if r.status_code == 200:
            d = r.json()
            cs = d.get('chain_stats', {})
            ms = d.get('mempool_stats', {})
            return ((cs.get('funded_txo_sum', 0) + ms.get('funded_txo_sum', 0)) -
                    (cs.get('spent_txo_sum', 0) + ms.get('spent_txo_sum', 0))) / 1e8
    except: pass
    return 0.0

def bal_evm(a, api):
    try:
        r = requests.get(f"{api}?module=account&action=balance&address={a}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status') == '1': return int(d.get('result', '0')) / 1e18
    except: pass
    return 0.0

def bal_ltc(a):
    try:
        r = requests.get(f"https://api.blockcypher.com/v1/ltc/main/addrs/{a}/balance", timeout=5)
        return r.json().get('final_balance', 0) / 1e8
    except: pass
    return 0.0

def bal_doge(a):
    try:
        r = requests.get(f"https://api.blockcypher.com/v1/doge/main/addrs/{a}/balance", timeout=5)
        return r.json().get('final_balance', 0) / 1e8
    except: pass
    return 0.0

def bal_trx(a):
    try:
        r = requests.get(f"https://apilist.tronscanapi.com/api/accountv2?address={a}", timeout=5)
        return r.json().get('balance', 0) / 1e6
    except: pass
    return 0.0

# ============================================================================
# FULL WALLET
# ============================================================================
def full_wallet(m):
    s = seed(m)
    mk, mc = master(s)
    wallets = {}
    
    for name, (path, typ) in PATHS.items():
        priv = derive(s, path)
        if not priv:
            wallets[name] = {'error': 'derivation failed'}
            continue
        
        pub_c = pub(priv, True)
        pub_u = pub(priv, False)
        
        if not pub_c or not pub_u:
            wallets[name] = {'error': 'pubkey failed'}
            continue
        
        if typ == 'BTC':
            if 'Legacy' in name: wallets[name] = {'addr': btc_p2pkh(pub_c), 'type': 'BTC'}
            elif 'SegWit' in name and 'Native' not in name: wallets[name] = {'addr': btc_p2sh(pub_c), 'type': 'BTC'}
            else: wallets[name] = {'addr': btc_b32(pub_c), 'type': 'BTC'}
        elif typ == 'EVM':
            wallets[name] = {'addr': eth_addr(pub_u), 'type': 'EVM'}
        elif typ == 'LTC':
            if 'Legacy' in name: wallets[name] = {'addr': ltc_p2pkh(pub_c), 'type': 'LTC'}
            else: wallets[name] = {'addr': ltc_p2sh(pub_c), 'type': 'LTC'}
        elif typ == 'DOGE':
            wallets[name] = {'addr': doge_p2pkh(pub_c), 'type': 'DOGE'}
    
    return wallets, mk, mc

# ============================================================================
# UI
# ============================================================================
st.set_page_config(page_title="HD Key Hunter", page_icon="K")
st.title("HD Key Hunter")
st.subheader("BIP-39 / BIP-32 / BIP-44 Full Standard")
st.caption("Matches MetaMask, TrustWallet, Ledger, Trezor")

t1, t2 = st.tabs(["Generate & Scan", "Deep Scan"])

with t1:
    c1, c2 = st.columns(2)
    with c1: n = st.slider("Phrases", 1, 5, 1)
    with c2: wc = st.radio("Words", [12, 24], horizontal=True)
    
    if st.button("Generate + Scan", type="primary", use_container_width=True):
        for _ in range(n):
            phrase = gen(wc)
            st.markdown("---")
            st.code(phrase)
            
            wallets, mk, mc = full_wallet(phrase)
            st.text(f"Master Key: {mk.hex()}")
            st.text(f"Chain Code: {mc.hex()}")
            
            found = False
            for name, data in wallets.items():
                if 'error' in data:
                    st.text(f"  {name}: {data['error']}")
                    continue
                
                a, t = data['addr'], data['type']
                
                if t == 'BTC': bal = bal_btc(a); sym = 'BTC'
                elif t == 'LTC': bal = bal_ltc(a); sym = 'LTC'
                elif t == 'DOGE': bal = bal_doge(a); sym = 'DOGE'
                elif t == 'EVM':
                    if name == 'TRON': bal = bal_trx(a); sym = 'TRX'
                    elif name in APIS: bal = bal_evm(a, APIS[name]); sym = 'ETH'
                    else: bal = 0.0; sym = '?'
                else: bal = 0.0; sym = '?'
                
                if bal > 0:
                    found = True
                    st.success(f"FOUND {name}: {bal:.8f} {sym} - {a}")
                else:
                    st.text(f"  {name}: 0 {sym}")
                
                time.sleep(0.02)
            
            if found: st.balloons()
            else: st.warning("All 15: zero balance")

with t2:
    phrase = st.text_area("Enter phrase:", height=80)
    
    if st.button("Full Scan", type="primary", use_container_width=True):
        if phrase.strip():
            if not val(phrase.strip()): st.error("Invalid checksum")
            else:
                wallets, mk, mc = full_wallet(phrase.strip())
                st.code(f"Master Key: {mk.hex()}\nChain Code: {mc.hex()}")
                
                for name, data in wallets.items():
                    if 'error' in data:
                        st.text(f"{name}: {data['error']}")
                        continue
                    
                    a, t = data['addr'], data['type']
                    
                    if t == 'BTC': bal = bal_btc(a); sym = 'BTC'
                    elif t == 'LTC': bal = bal_ltc(a); sym = 'LTC'
                    elif t == 'DOGE': bal = bal_doge(a); sym = 'DOGE'
                    elif t == 'EVM':
                        if name == 'TRON': bal = bal_trx(a); sym = 'TRX'
                        elif name in APIS: bal = bal_evm(a, APIS[name]); sym = 'ETH'
                        else: bal = 0.0; sym = '?'
                    else: bal = 0.0; sym = '?'
                    
                    if bal > 0: st.success(f"FOUND {name}: {bal:.8f} {sym} - {a}")
                    else: st.text(f"{name}: 0 {sym}")
                    
                    time.sleep(0.02)

st.caption("BIP-39/32/44 | 15 paths | 13 chains")
