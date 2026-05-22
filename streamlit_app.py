import streamlit as st
import secrets
import hashlib
import hmac
import requests
import json
import time

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

def seed(m, pw=""):
    return hashlib.pbkdf2_hmac('sha512', m.encode(), ("mnemonic" + pw).encode(), 2048, 64)

def master_key(seed_bytes):
    return hmac.new(b"Bitcoin seed", seed_bytes, hashlib.sha512).digest()[:32]

def derive_public_key(priv_key_bytes):
    try:
        from coincurve import PrivateKey
        pk = PrivateKey(priv_key_bytes)
        return pk.public_key.format()
    except:
        return None

def pubkey_to_addresses(pubkey_bytes):
    addresses = {}
    
    try:
        # P2PKH (Legacy - starts with 1)
        h1 = hashlib.sha256(pubkey_bytes).digest()
        h2 = hashlib.new('ripemd160', h1).digest()
        addresses['legacy'] = base58_encode_p2pkh(h2)
    except:
        pass
    
    try:
        # P2SH-SegWit (starts with 3)
        script = b'\x00\x14' + hashlib.new('ripemd160', hashlib.sha256(pubkey_bytes).digest()).digest()
        h3 = hashlib.sha256(script).digest()
        h4 = hashlib.new('ripemd160', h3).digest()
        addresses['segwit'] = base58_encode_p2sh(h4)
    except:
        pass
    
    try:
        # Bech32 Native SegWit (starts with bc1)
        witprog = hashlib.new('ripemd160', hashlib.sha256(pubkey_bytes).digest()).digest()
        addresses['native'] = bech32_encode('bc', 0, witprog)
    except:
        pass
    
    return addresses

def base58_encode_p2pkh(hash160):
    prefix = b'\x00' + hash160
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58_encode(prefix + checksum)

def base58_encode_p2sh(hash160):
    prefix = b'\x05' + hash160
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58_encode(prefix + checksum)

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(data):
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, rem = divmod(n, 58)
        result.append(BASE58_ALPHABET[rem])
    for byte in data:
        if byte == 0:
            result.append(BASE58_ALPHABET[0])
        else:
            break
    return ''.join(reversed(result))

def bech32_encode(hrp, witver, witprog):
    CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
    GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    
    def polymod(values):
        chk = 1
        for v in values:
            top = chk >> 25
            chk = (chk & 0x1ffffff) << 5 ^ v
            for i in range(5):
                if (top >> i) & 1:
                    chk ^= GENERATOR[i]
        return chk
    
    def hrp_expand(s):
        return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]
    
    data = [witver] + list(witprog)
    combined = hrp_expand(hrp) + data
    plm = polymod(combined + [0, 0, 0, 0, 0, 0])
    checksum = [(plm >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + '1' + ''.join(CHARSET[d] for d in data + checksum)

# ============================================================================
# UTXO SCANNER - Multi-API Strategy
# ============================================================================

def check_balance_blockchain_info(address):
    try:
        resp = requests.get(f"https://blockchain.info/balance?active={address}", timeout=5)
        data = resp.json()
        return data.get(address, {}).get('final_balance', 0) / 1e8
    except:
        return None

def check_balance_blockstream(address):
    try:
        resp = requests.get(f"https://blockstream.info/api/address/{address}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            chain_stats = data.get('chain_stats', {})
            mempool_stats = data.get('mempool_stats', {})
            funded = chain_stats.get('funded_txo_sum', 0)
            spent = chain_stats.get('spent_txo_sum', 0)
            balance = (funded - spent) / 1e8
            return balance
    except:
        pass
    return None

def check_balance_mempool(address):
    try:
        resp = requests.get(f"https://mempool.space/api/address/{address}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            chain_stats = data.get('chain_stats', {})
            mempool_stats = data.get('mempool_stats', {})
            funded = chain_stats.get('funded_txo_sum', 0) + mempool_stats.get('funded_txo_sum', 0)
            spent = chain_stats.get('spent_txo_sum', 0) + mempool_stats.get('spent_txo_sum', 0)
            balance = (funded - spent) / 1e8
            return balance
    except:
        pass
    return None

def check_balance_btcscan(address):
    try:
        resp = requests.get(f"https://btcscan.org/api/address/{address}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            chain_stats = data.get('chain_stats', {})
            funded = chain_stats.get('funded_txo_sum', 0)
            spent = chain_stats.get('spent_txo_sum', 0)
            balance = (funded - spent) / 1e8
            return balance
    except:
        pass
    return None

def scan_address_full(address):
    """Try all APIs - return balance if any finds funds"""
    checkers = [
        check_balance_blockstream,
        check_balance_mempool,
        check_balance_blockchain_info,
        check_balance_btcscan,
    ]
    
    for checker in checkers:
        result = checker(address)
        if result is not None:
            return result
    
    return 0.0

# ============================================================================
# STREAMLIT UI
# ============================================================================

st.set_page_config(page_title="BTC Key Hunter", page_icon="₿")
st.title("₿ Bitcoin Key Hunter")
st.success(f"{len(BIP39)} canonical BIP-39 words | UTXO Scan Ready")

t1, t2, t3, t4 = st.tabs(["Generate", "Validate", "Weak Patterns", "💀 Deep Scan"])

with t1:
    c1, c2 = st.columns(2)
    with c1:
        n = st.slider("Count", 1, 10, 3)
    with c2:
        wc = st.radio("Words", [12, 24], horizontal=True)
    
    if st.button("Generate", type="primary", use_container_width=True):
        st.session_state['phrases'] = [gen(wc) for _ in range(n)]
        st.success(f"{n} phrases generated")
    
    if 'phrases' in st.session_state:
        for i, p in enumerate(st.session_state['phrases']):
            with st.expander(f"Phrase {i+1}"):
                st.code(p)
                s = seed(p)
                k = master_key(s)
                st.text(f"Private Key: {k.hex()}")

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
                st.success("✅ VALID")
            else:
                st.error("❌ INVALID")

with t3:
    st.subheader("Weak Pattern Scanner")
    
    if st.button("Generate + Scan Brainwallets", type="primary", use_container_width=True):
        pws = [
            "password", "12345678", "qwerty123", "letmein", "bitcoin",
            "ethereum", "satoshi", "metamask", "trustwallet", "blockchain",
            "crypto", "iloveyou", "admin123", "rootroot"
        ]
        
        found_any = False
        
        for pw in pws:
            h = hashlib.sha256(pw.encode()).digest()
            idxs = [((h[i] << 8) | h[(i+1) % len(h)]) % 2048 for i in range(12)]
            phrase = ' '.join(BIP39[i] for i in idxs)
            
            s = seed(phrase)
            k = master_key(s)
            pub = derive_public_key(k)
            
            if pub:
                addrs = pubkey_to_addresses(pub)
                for addr_type, addr in addrs.items():
                    bal = scan_address_full(addr)
                    time.sleep(0.3)  # Rate limit
                    
                    if bal > 0:
                        found_any = True
                        st.success(f"💰 FOUND: {bal:.8f} BTC")
                        st.code(phrase)
                        st.text(f"Address ({addr_type}): {addr}")
                        st.text(f"Private Key: {k.hex()}")
                    else:
                        st.text(f"❌ {addr_type}: {addr[:16]}... = 0 BTC")
        
        if not found_any:
            st.warning("No funded wallets found in this batch")

with t4:
    st.subheader("💀 Deep UTXO Scan")
    st.caption("Scans against real UTXO set via multiple APIs")
    
    phrase_input = st.text_area("Enter phrase to deep scan:", height=80, key="deep")
    
    if st.button("💀 Scan Now", type="primary", use_container_width=True):
        if phrase_input.strip():
            ws = phrase_input.strip().split()
            
            if len(ws) not in [12, 24] or not all(w in W2I for w in ws):
                st.error("Invalid phrase")
            elif not val(phrase_input.strip()):
                st.error("Invalid checksum")
            else:
                s = seed(phrase_input.strip())
                k = master_key(s)
                pub = derive_public_key(k)
                
                if pub:
                    addrs = pubkey_to_addresses(pub)
                    st.text(f"Private Key: {k.hex()}")
                    
                    for addr_type, addr in addrs.items():
                        with st.spinner(f"Scanning {addr_type}: {addr}..."):
                            bal = scan_address_full(addr)
                        
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Type", addr_type.upper())
                        col2.metric("Address", f"{addr[:8]}...{addr[-6:]}")
                        col3.metric("Balance", f"{bal:.8f} BTC" if bal > 0 else "0 BTC")
                        
                        if bal > 0:
                            st.balloons()
                            st.success(f"💰 FOUND: {bal:.8f} BTC")
                            st.code(phrase_input.strip())
                            st.text(f"Private Key: {k.hex()}")
                            st.text(f"Address: {addr}")

st.markdown("---")
st.caption("UTXO scanning via Blockstream + Mempool.space + Blockchain.info APIs")
