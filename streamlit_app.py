import streamlit as st
import secrets
import hashlib
import hmac
import requests
import json
import time
from typing import Dict, Optional

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
# CORE FUNCTIONS
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

def seed(m, pw=""):
    return hashlib.pbkdf2_hmac('sha512', m.encode(), ("mnemonic" + pw).encode(), 2048, 64)

def master_key(seed_bytes):
    return hmac.new(b"Bitcoin seed", seed_bytes, hashlib.sha512).digest()[:32]

# ============================================================================
# ADDRESS GENERATORS - ALL CHAINS
# ============================================================================
def priv_to_eth_address(priv):
    try:
        from eth_keys import keys
        pk = keys.PrivateKey(priv)
        return pk.public_key.to_checksum_address()
    except:
        return None

def priv_to_btc_addresses(priv):
    try:
        from coincurve import PrivateKey
        pk = PrivateKey(priv)
        pub = pk.public_key.format()
        h1 = hashlib.sha256(pub).digest()
        h2 = hashlib.new('ripemd160', h1).digest()
        return {'BTC': base58_encode(b'\x00' + h2)}
    except:
        return {}

BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def base58_encode(data):
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

# ============================================================================
# MULTI-CHAIN BALANCE CHECKERS
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

def check_eth(addr):
    apis = [
        f"https://api.etherscan.io/api?module=account&action=balance&address={addr}&tag=latest",
        f"https://eth.llamarpc.com",
    ]
    try:
        r = requests.get(apis[0], timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e18
    except:
        pass
    return 0.0

def check_bsc(addr):
    try:
        r = requests.get(f"https://api.bscscan.com/api?module=account&action=balance&address={addr}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e18
    except:
        pass
    return 0.0

def check_polygon(addr):
    try:
        r = requests.get(f"https://api.polygonscan.com/api?module=account&action=balance&address={addr}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e18
    except:
        pass
    return 0.0

def check_avax(addr):
    try:
        r = requests.get(f"https://api.routescan.io/v2/network/mainnet/evm/43114/etherscan/api?module=account&action=balance&address={addr}", timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e18
    except:
        pass
    return 0.0

def check_ftm(addr):
    try:
        r = requests.get(f"https://api.ftmscan.com/api?module=account&action=balance&address={addr}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e18
    except:
        pass
    return 0.0

def check_arb(addr):
    try:
        r = requests.get(f"https://api.arbiscan.io/api?module=account&action=balance&address={addr}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e18
    except:
        pass
    return 0.0

def check_op(addr):
    try:
        r = requests.get(f"https://api-optimistic.etherscan.io/api?module=account&action=balance&address={addr}&tag=latest", timeout=5)
        d = r.json()
        if d.get('status') == '1':
            return int(d.get('result', 0)) / 1e18
    except:
        pass
    return 0.0

def check_base(addr):
    try:
        r = requests.get(f"https://api.basescan.org/api?module=account&action=balance&address={addr}&tag=latest", timeout=5)
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
        d = r.json()
        return float(d.get('balance', 0))
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
        d = r.json()
        return d.get('result', {}).get('value', 0) / 1e9
    except:
        pass
    return 0.0

# ============================================================================
# SCAN ENGINE
# ============================================================================
CHAINS = {
    'BTC': check_btc,
    'ETH': check_eth,
    'BNB': check_bsc,
    'MATIC': check_polygon,
    'AVAX': check_avax,
    'FTM': check_ftm,
    'ARB': check_arb,
    'OP': check_op,
    'BASE': check_base,
    'TRX': check_trx,
    'DOGE': check_doge,
    'LTC': check_ltc,
    'SOL': check_sol,
}

def scan_all_chains(eth_addr, btc_addr=None):
    results = {}
    
    if eth_addr:
        for chain, checker in CHAINS.items():
            if chain == 'BTC':
                continue
            try:
                bal = checker(eth_addr)
                if bal > 0:
                    results[chain] = bal
                time.sleep(0.05)
            except:
                pass
    
    if btc_addr:
        try:
            bal = check_btc(btc_addr)
            if bal > 0:
                results['BTC'] = bal
        except:
            pass
    
    return results

# ============================================================================
# UI
# ============================================================================
st.set_page_config(page_title="Multi-Chain Key Hunter", page_icon="💻")
st.title("💻 Multi-Chain Key Hunter")
st.success(f"{len(BIP39)} BIP-39 words | 13 Chains: BTC ETH BNB MATIC AVAX FTM ARB OP BASE TRX DOGE LTC SOL")

t1, t2, t3, t4 = st.tabs(["Generate", "Validate", "Brainwallets", "💻 Deep Scan"])

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
                st.success("✔️ VALID")
            else:
                st.error("❌ INVALID")

with t3:
    if st.button("Generate + Scan Brainwallets", type="primary", use_container_width=True):
        pws = [
            "password", "12345678", "qwerty123", "letmein", "bitcoin",
            "ethereum", "satoshi", "metamask", "trustwallet", "blockchain",
            "crypto", "iloveyou", "admin123", "rootroot", "passw0rd",
            "dragon", "monkey", "master", "shadow", "sunshine"
        ]
        
        found_any = False
        
        for pw in pws:
            h = hashlib.sha256(pw.encode()).digest()
            idxs = [((h[i] << 8) | h[(i+1) % len(h)]) % 2048 for i in range(12)]
            phrase = ' '.join(BIP39[i] for i in idxs)
            s = seed(phrase)
            k = master_key(s)
            
            eth_addr = priv_to_eth_address(k)
            btc_addrs = priv_to_btc_addresses(k)
            btc_addr = btc_addrs.get('BTC') if btc_addrs else None
            
            results = scan_all_chains(eth_addr, btc_addr)
            
            if results:
                found_any = True
                for chain, bal in results.items():
                    st.success(f"💰 {chain}: {bal:.6f}")
                st.code(phrase)
                st.text(f"ETH: {eth_addr}")
                if btc_addr:
                    st.text(f"BTC: {btc_addr}")
            else:
                st.text(f"❌ {pw} → 0 on all chains")
            time.sleep(0.1)
        
        if not found_any:
            st.warning("No funded wallets found")

with t4:
    st.subheader("💻 Deep Multi-Chain Scan")
    
    phrase_input = st.text_area("Enter phrase:", height=80, key="deep")
    
    if st.button("💻 Scan All 13 Chains", type="primary", use_container_width=True):
        if phrase_input.strip():
            ws = phrase_input.strip().split()
            
            if not val(phrase_input.strip()):
                st.error("Invalid phrase")
            else:
                s = seed(phrase_input.strip())
                k = master_key(s)
                
                eth_addr = priv_to_eth_address(k)
                btc_addrs = priv_to_btc_addresses(k)
                btc_addr = btc_addrs.get('BTC') if btc_addrs else None
                
                st.text(f"Private Key: {k.hex()}")
                st.text(f"ETH Address: {eth_addr}")
                if btc_addr:
                    st.text(f"BTC Address: {btc_addr}")
                
                st.markdown("---")
                
                progress = st.progress(0)
                results = {}
                
                chains_list = list(CHAINS.items())
                for i, (chain, checker) in enumerate(chains_list):
                    addr = btc_addr if chain == 'BTC' else eth_addr
                    if addr:
                        try:
                            bal = checker(addr)
                            if bal > 0:
                                results[chain] = bal
                        except:
                            pass
                    progress.progress((i + 1) / len(chains_list))
                    time.sleep(0.05)
                
                progress.empty()
                
                if results:
                    st.success(f"💰 FOUND FUNDS!")
                    for chain, bal in results.items():
                        st.metric(chain, f"{bal:.8f}")
                    st.code(phrase_input.strip())
                    st.text(f"Private Key: {k.hex()}")
                else:
                    st.warning("0 balance on all 13 chains")
                    for chain in CHAINS:
                        st.text(f"  ❌ {chain}: 0")

st.markdown("---")
st.caption("13 Chains: BTC ETH BNB MATIC AVAX FTM ARB OP BASE TRX DOGE LTC SOL")
