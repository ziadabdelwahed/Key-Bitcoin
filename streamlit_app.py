import streamlit as st
import secrets
import hashlib
import hmac
import requests

@st.cache_data
def load_words():
    r = requests.get("https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt")
    words = r.text.strip().split("\n")
    return words

BIP39 = load_words()
st.success(f"Loaded: {len(BIP39)} words")

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

st.set_page_config(page_title="BTC Key Hunter", page_icon="₿")
st.title("₿ Bitcoin Key Hunter")

t1, t2, t3 = st.tabs(["Generate", "Validate", "Weak Patterns"])

with t1:
    c1, c2 = st.columns(2)
    with c1:
        n = st.slider("Count", 1, 20, 5)
    with c2:
        wc = st.radio("Words", [12, 24], horizontal=True)
    
    if st.button("Generate", type="primary", use_container_width=True):
        st.session_state['phrases'] = [gen(wc) for _ in range(n)]
        st.success(f"Generated {n} valid phrases")
    
    if 'phrases' in st.session_state:
        for i, p in enumerate(st.session_state['phrases']):
            with st.expander(f"✔️ Phrase {i+1}"):
                st.code(p)
                s = seed(p)
                k = hmac.new(b"Bitcoin seed", s, hashlib.sha512).digest()[:32]
                st.text(f"Key: {k.hex()}")

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
                st.success("✔️ VALID — Works in all wallets")
            else:
                st.error("❌ INVALID checksum")

with t3:
    if st.button("Brainwallets", type="primary", use_container_width=True):
        pws = ["password","12345678","qwerty123","letmein","bitcoin","ethereum","satoshi","metamask","trustwallet","blockchain"]
        phrases = []
        for pw in pws:
            h = hashlib.sha256(pw.encode()).digest()
            idxs = [((h[i] << 8) | h[(i+1) % len(h)]) % 2048 for i in range(12)]
            phrases.append(' '.join(BIP39[i] for i in idxs))
        st.session_state['weak'] = phrases
    
    if 'weak' in st.session_state:
        for i, p in enumerate(st.session_state['weak']):
            with st.expander(f"Phrase {i+1}"):
                st.code(p)

st.caption("Words from BIP-39 GitHub | 100% compatible")
