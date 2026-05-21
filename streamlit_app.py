import streamlit as st
import secrets
import hashlib
import hmac

BIP39_WORDS = []
with open("bip39_words.txt", "w") as f:
    import requests
    url = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"
    words = requests.get(url).text.strip().split("\n")
    BIP39_WORDS = words
    f.write("\n".join(words))

def mnemonic_to_seed(mnemonic, passphrase=""):
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048, 64)

def random_phrase(n=12):
    return ' '.join(secrets.choice(BIP39_WORDS) for _ in range(n))

st.set_page_config(page_title="Phantom Key Hunter", page_icon="🔑")
st.title("🔑 Phantom Key Hunter")
st.subheader("BIP-39 Mnemonic Generator & Scanner")

st.markdown("---")

tab1, tab2 = st.tabs(["🎲 Generate", "🔍 Scan"])

with tab1:
    st.subheader("Generate Mnemonic Phrases")
    
    col1, col2 = st.columns(2)
    with col1:
        count = st.slider("Number of phrases", 1, 100, 5)
    with col2:
        words_count = st.radio("Words per phrase", [12, 24], horizontal=True)
    
    if st.button("🎲 Generate", type="primary", use_container_width=True):
        phrases = [random_phrase(words_count) for _ in range(count)]
        st.session_state['phrases'] = phrases
        st.success(f"Generated {count} phrases")

    if 'phrases' in st.session_state:
        st.markdown("### Results")
        for i, phrase in enumerate(st.session_state['phrases']):
            with st.expander(f"Phrase {i+1}"):
                st.code(phrase)
                seed = mnemonic_to_seed(phrase)
                pk = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[:32]
                st.text(f"Private Key: {pk.hex()}")

with tab2:
    st.subheader("Scan Single Phrase")
    
    phrase = st.text_area("Enter BIP-39 mnemonic:", height=80,
                          placeholder="word1 word2 ... word12")
    
    if st.button("🔍 Analyze", type="primary", use_container_width=True):
        if phrase.strip():
            words = phrase.strip().split()
            if len(words) in [12, 24] and all(w in BIP39_WORDS for w in words):
                seed = mnemonic_to_seed(phrase)
                pk = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[:32]
                
                st.success("✅ Valid BIP-39 mnemonic")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Words", len(words))
                    st.text(f"Seed: {seed.hex()[:32]}...")
                with col2:
                    st.metric("Strength", f"{len(words)*11} bits")
                    st.text(f"Key: {pk.hex()[:32]}...")
            else:
                st.error("Invalid mnemonic")

st.markdown("---")
st.caption("Research tool | Use only on wallets you own")
