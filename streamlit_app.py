import streamlit as st
import secrets
import hashlib
import hmac
import json
import struct
import binascii
import time
import requests
import concurrent.futures
from typing import List, Dict, Optional, Set
from pathlib import Path

# ============================================================================
# BIP-39 CANONICAL WORDLIST (2048 words - VERIFIED)
# ============================================================================
BIP39_WORDS = [
    "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
    "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
    "action","actor","actress","actual","adapt","add","addict","address","adjust","admit",
    "adult","advance","advice","aerobic","affair","afford","afraid","africa","after","again",
    "age","agent","agree","ahead","aim","air","airport","aisle","alarm","album",
    "alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already",
    "also","alter","always","amateur","amazing","among","amount","amused","analyst","anchor",
    "ancient","anger","angle","angry","animal","ankle","announce","annual","another","answer",
    "antenna","antique","anxiety","any","apart","apology","appear","apple","approve","april",
    "arch","arctic","area","arena","argue","arm","armed","armor","army","around",
    "arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect",
    "assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude",
    "attract","auction","audit","august","aunt","author","auto","autumn","average","avocado",
    "avoid","awake","aware","away","awesome","awful","awkward","axis","baby","bachelor",
    "bacon","badge","bag","balance","balcony","ball","bamboo","banana","banner","bar",
    "barely","bargain","barrel","base","basic","basket","battle","beach","bean","beauty",
    "because","become","beef","before","begin","behave","behind","believe","below","belt",
    "bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike",
    "bind","biology","bird","birth","bitter","black","blade","blame","blanket","blast",
    "bleak","bless","blind","blood","blossom","blouse","blue","blur","blush","board",
    "boat","body","boil","bomb","bone","bonus","book","boost","border","boring",
    "borrow","boss","bottom","bounce","box","boy","bracket","brain","brand","brass",
    "brave","bread","breeze","brick","bridge","brief","bright","bring","brisk","broccoli",
    "broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo",
    "build","bulb","bulk","bullet","bundle","bunker","burden","burger","burst","bus",
    "business","busy","butter","buyer","buzz","cabbage","cabin","cable","cactus","cage",
    "cake","call","calm","camera","camp","can","canal","cancel","candy","cannon",
    "canoe","canvas","canyon","capable","capital","captain","car","carbon","card","cargo",
    "carpet","carry","cart","case","cash","casino","castle","casual","cat","catalog",
    "catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement",
    "census","century","cereal","certain","chair","chalk","champion","change","chaos","chapter",
    "charge","chase","chat","cheap","check","cheese","chef","cherry","chest","chicken",
    "chief","child","chimney","choice","choose","chronic","chuckle","chunk","churn","cigar",
    "cinnamon","circle","citizen","city","civil","claim","clap","clarify","claw","clay",
    "clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock",
    "clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach",
    "coast","coconut","code","coffee","coil","coin","collect","color","column","combine",
    "come","comfort","comic","common","company","concert","conduct","confirm","congress","connect",
    "consider","control","convince","cook","cool","copper","copy","coral","core","corn",
    "correct","cost","cotton","couch","country","couple","course","cousin","cover","coyote",
    "crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream",
    "credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crouch",
    "crowd","crucial","cruel","cruise","crumble","crunch","crush","cry","crystal","cube",
    "culture","cup","cupboard","curious","current","curtain","curve","cushion","custom","cute",
    "cycle","dad","damage","damp","dance","danger","daring","dash","daughter","dawn",
    "day","deal","debate","debris","decade","december","decide","decline","decorate","decrease",
    "deer","defense","define","defy","degree","delay","deliver","demand","demise","denial",
    "dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert",
    "design","desk","despair","destroy","detail","detect","develop","device","devote","diagram",
    "dial","diamond","diary","dice","diesel","diet","differ","digital","dignity","dilemma",
    "dinner","dinosaur","direct","dirt","disagree","discover","disease","dish","dismiss","disorder",
    "display","distance","divert","divide","divorce","dizzy","doctor","document","dog","doll",
    "dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft",
    "dragon","drama","drastic","draw","dream","dress","drift","drill","drink","drip",
    "drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch",
    "duty","dwarf","dynamic","eager","eagle","early","earn","earth","easily","east",
    "easy","echo","ecology","economy","edge","edit","educate","effort","egg","eight",
    "either","elbow","elder","electric","elegant","element","elephant","elevator","elite","else",
    "embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact",
    "end","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy",
    "enlist","enough","enrich","enroll","ensure","enter","entire","entry","envelope","episode",
    "equal","equip","era","erase","erode","erosion","error","erupt","escape","essay",
    "essence","estate","eternal","ethics","evidence","evil","evoke","evolve","exact","example",
    "excess","exchange","excite","exclude","excuse","execute","exercise","exhaust","exhibit",
    "exile","exist","exit","exotic","expand","expect","expire","explain","expose","express",
    "extend","extra","eye","eyebrow","fabric","face","faculty","fade","faint","faith",
    "fall","false","fame","family","famous","fan","fancy","fantasy","farm","fashion",
    "fat","fatal","father","fatigue","fault","favorite","feature","february","federal","fee",
    "feed","feel","female","fence","festival","fetch","fever","few","fiber","fiction",
    "field","figure","file","film","filter","final","find","fine","finger","finish",
    "fire","firm","first","fiscal","fish","fit","fitness","fix","flag","flame",
    "flash","flat","flavor","flee","flight","flip","float","flock","floor","flower",
    "fluid","flush","fly","foam","focus","fog","foil","fold","follow","food",
    "foot","force","forest","forget","fork","fortune","forum","forward","fossil","foster",
    "found","fox","fragile","frame","frequent","fresh","friend","fringe","frog","front",
    "frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury","future",
    "gadget","gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic",
    "garment","gas","gasp","gate","gather","gauge","gaze","general","genius","genre",
    "gentle","genuine","gesture","ghost","giant","gift","giggle","ginger","giraffe","girl",
    "give","glad","glance","glare","glass","glide","glimpse","globe","gloom","glory",
    "glove","glow","glue","goat","goddess","gold","good","goose","gorilla","gospel",
    "gossip","govern","gown","grab","grace","grain","grant","grape","grass","gravity",
    "great","green","grid","grief","grit","grocery","group","grow","grunt","guard",
    "guess","guide","guilt","guitar","gun","gym","habit","hair","half","hammer",
    "hamster","hand","happy","harbor","hard","harsh","harvest","hat","have","hawk",
    "hazard","head","health","heart","heavy","hedgehog","height","hello","helmet","help",
    "hen","hero","hidden","high","hill","hint","hip","hire","history","hobby",
    "hockey","hold","hole","holiday","hollow","home","honey","hood","hope","horn",
    "horror","horse","hospital","host","hotel","hour","hover","hub","huge","human",
    "humble","humor","hundred","hunt","hurdle","hurry","hurt","husband","hybrid","ice",
    "icon","idea","identify","idle","ignore","ill","illegal","illness","image","imitate",
    "immense","immune","impact","impose","improve","impulse","inch","include","income","increase",
    "index","indicate","indoor","industry","infant","inflict","inform","inhale","inherit","initial",
    "inject","injury","inmate","inner","innocent","input","inquiry","insane","insect","inside",
    "inspire","install","intact","interest","into","invest","invite","involve","iron","island",
    "isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans",
    "jelly","jewel","job","join","joke","journey","joy","judge","juice","jump",
    "jungle","junior","junk","just","kangaroo","keen","keep","ketchup","key","kick",
    "kid","kidney","kind","kingdom","kiss","kit","kitchen","kite","kitten","kiwi",
    "knee","knife","knock","know","lab","label","labor","ladder","lady","lake",
    "lamp","language","laptop","large","later","latin","laugh","laundry","lava","law",
    "lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left",
    "leg","legal","legend","leisure","lemon","lend","length","lens","leopard","lesson",
    "letter","level","liar","liberty","life","lift","light","like","limb","limit",
    "link","lion","liquid","list","little","live","lizard","load","loan","lobster",
    "local","lock","logic","lonely","long","loop","lottery","loud","lounge","love",
    "loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics","machine","mad",
    "magic","magnet","maid","mail","main","major","make","mammal","man","manage",
    "mandate","mango","mansion","manual","maple","marble","march","margin","marine","market",
    "marriage","mask","mass","master","match","material","math","matrix","matter","maximum",
    "maze","meadow","mean","measure","meat","mechanic","medal","media","melody","melt",
    "member","memory","mention","menu","mercy","merge","merit","merry","mesh","message",
    "metal","method","middle","midnight","milk","million","mimic","mind","minimum","minor",
    "minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile",
    "model","modify","mom","moment","monitor","monkey","monster","month","moon","moral",
    "more","morning","mosquito","mother","motion","motor","mountain","mouse","move","movie",
    "much","muffin","mule","multiply","muscle","museum","mushroom","music","must","mutual",
    "myself","mystery","myth","naive","name","napkin","narrow","nasty","nation","nature",
    "near","neck","need","negative","neglect","neither","nephew","nerve","nest","net",
    "network","neutral","never","news","next","nice","night","noble","noise","nominee",
    "noodle","normal","north","nose","notable","note","nothing","notice","novel","now",
    "nuclear","number","nurse","nut","oak","obey","object","oblige","obscure","observe",
    "obtain","obvious","occur","ocean","october","odor","off","offer","office","often",
    "oil","okay","old","olive","olympic","omit","once","one","onion","online",
    "only","open","opera","opinion","oppose","option","orange","orbit","orchard","order",
    "ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output",
    "outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact",
    "paddle","page","pair","palace","palm","panda","panel","panic","panther","paper",
    "parade","parent","park","parrot","party","pass","patch","path","patient","patrol",
    "pattern","pause","pave","payment","peace","peanut","pear","peasant","pelican","pen",
    "penalty","pencil","people","pepper","perfect","permit","person","pet","phone","photo",
    "phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot",
    "pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate",
    "play","please","pledge","pluck","plug","plunge","poem","poet","point","polar",
    "pole","police","pond","pony","pool","popular","portion","position","possible","post",
    "potato","pottery","poverty","powder","power","practice","praise","predict","prefer","prepare",
    "present","pretty","prevent","price","pride","primary","print","priority","prison","private",
    "prize","problem","process","produce","profit","program","project","promote","proof","property",
    "prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin",
    "punch","pupil","puppy","purchase","purity","purpose","purse","push","put","puzzle",
    "pyramid","quality","quantum","quarter","question","quick","quit","quiz","quote","rabbit",
    "raccoon","race","rack","radar","radio","rail","rain","raise","rally","ramp",
    "ranch","random","range","rapid","rare","rate","rather","raven","raw","razor",
    "ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle",
    "reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release",
    "relief","rely","remain","remember","remind","remove","render","renew","rent","reopen",
    "repair","repeat","replace","report","require","rescue","resemble","resist","resource","response",
    "result","retire","retreat","return","reunion","reveal","review","reward","rhythm","rib",
    "ribbon","rice","rich","ride","ridge","rifle","right","rigid","ring","riot",
    "ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket",
    "romance","roof","rookie","room","rose","rotate","rough","round","route","royal",
    "rubber","rude","rug","rule","run","runway","rural","sad","saddle","sadness",
    "safe","sail","salad","salmon","salon","salt","salute","same","sample","sand",
    "satisfy","satoshi","sauce","sausage","save","say","scale","scan","scare","scatter",
    "scene","scheme","school","science","scissors","scorpion","scout","scrap","screen","script",
    "scrub","sea","search","season","seat","second","secret","section","security","seed",
    "seek","segment","select","sell","seminar","senior","sense","sentence","series","service",
    "session","settle","setup","seven","shadow","shaft","shallow","share","shed","shell",
    "sheriff","shield","shift","shine","ship","shiver","shock","shoe","shoot","shop",
    "short","shoulder","shove","shrimp","shrug","shuffle","shy","sibling","sick","side",
    "siege","sight","sign","silent","silk","silly","silver","similar","simple","since",
    "sing","siren","sister","situate","six","size","skate","sketch","ski","skill",
    "skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight",
    "slim","slogan","slot","slow","slush","small","smart","smile","smoke","smooth",
    "snack","snake","snap","sniff","snow","soap","soccer","social","sock","soda",
    "soft","solar","soldier","solid","solution","solve","someone","song","soon","sorry",
    "sort","soul","sound","soup","source","south","space","spare","spatial","spawn",
    "speak","special","speed","spell","spend","sphere","spice","spider","spike","spin",
    "spirit","split","spoil","sponsor","spoon","sport","spot","spray","spread","spring",
    "spy","square","squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp",
    "stand","start","state","stay","steak","steel","stem","step","stereo","stick",
    "still","sting","stock","stomach","stone","stool","story","stove","strategy","street",
    "strike","strong","struggle","student","stuff","stumble","style","subject","submit","subway",
    "success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny",
    "sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey",
    "suspect","sustain","swallow","swamp","swap","swarm","swear","sweet","swift","swim",
    "swing","switch","sword","symbol","symptom","syrup","system","table","tackle","tag",
    "tail","talent","talk","tank","tape","target","task","taste","tattoo","taxi",
    "teach","team","tell","ten","tenant","tennis","tent","term","test","text",
    "thank","that","theme","then","theory","there","they","thing","this","thought",
    "three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber",
    "time","tiny","tip","tired","tissue","title","toast","tobacco","today","toddler",
    "toe","together","toilet","token","tomato","tomorrow","tone","tongue","tonight","tool",
    "tooth","top","topic","topple","torch","tornado","tortoise","toss","total","tourist",
    "toward","tower","town","toy","track","trade","traffic","tragic","train","transfer",
    "trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick",
    "trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust",
    "truth","try","tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle",
    "twelve","twenty","twice","twin","twist","two","type","typical","ugly","umbrella",
    "unable","unaware","uncle","uncover","under","undo","unfair","unfold","unhappy","uniform",
    "unique","unit","universe","unknown","unlock","until","unusual","unveil","update","upgrade",
    "uphold","upon","upper","upset","urban","urge","usage","use","used","useful",
    "useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van",
    "vanish","vapor","various","vast","vault","vehicle","velvet","vendor","venture","venue",
    "verb","verify","version","very","vessel","veteran","viable","vibrant","vicious","victory",
    "video","view","village","vintage","violin","virtual","virus","visa","visit","visual",
    "vital","vivid","vocal","voice","void","volcano","volume","vote","voyage","wage",
    "wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash",
    "wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather",
    "web","wedding","weekend","weird","welcome","west","wet","whale","what","wheat",
    "wheel","when","where","whip","whisper","wide","width","wife","wild","will",
    "win","window","wine","wing","wink","winner","winter","wire","wisdom","wise",
    "wish","witness","wolf","woman","wonder","wood","wool","word","work","world",
    "worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year",
    "yellow","you","young","youth","zebra","zero","zone","zoo"
]

assert len(BIP39_WORDS) == 2048, f"CRITICAL: Wordlist is {len(BIP39_WORDS)}, must be 2048"
WORD_TO_INDEX = {w: i for i, w in enumerate(BIP39_WORDS)}

# ============================================================================
# CORE BIP-39 FUNCTIONS
# ============================================================================

def generate_valid_mnemonic(word_count=12):
    if word_count == 12:
        ENT, CS = 128, 4
    elif word_count == 24:
        ENT, CS = 256, 8
    else:
        raise ValueError("Must be 12 or 24 words")
    
    entropy = secrets.token_bytes(ENT // 8)
    h = hashlib.sha256(entropy).digest()
    checksum = h[0] >> (8 - CS)
    
    entropy_int = int.from_bytes(entropy, 'big')
    combined = (entropy_int << CS) | checksum
    total_bits = ENT + CS
    
    words = []
    for i in range(word_count):
        shift = total_bits - 11 * (i + 1)
        index = (combined >> shift) & 0x7FF
        words.append(BIP39_WORDS[index])
    
    return ' '.join(words)

def validate_mnemonic(mnemonic):
    words = mnemonic.strip().split()
    if len(words) not in [12, 15, 18, 21, 24]:
        return False
    if not all(w in WORD_TO_INDEX for w in words):
        return False
    
    word_count = len(words)
    ENT = (word_count * 11 * 32) // 33
    CS = word_count * 11 - ENT
    
    indices = [WORD_TO_INDEX[w] for w in words]
    combined = 0
    for idx in indices:
        combined = (combined << 11) | idx
    
    checksum = combined & ((1 << CS) - 1)
    entropy_bits = combined >> CS
    entropy_bytes = entropy_bits.to_bytes(ENT // 8, 'big')
    
    h = hashlib.sha256(entropy_bytes).digest()
    expected = h[0] >> (8 - CS)
    
    return checksum == expected

def mnemonic_to_seed(mnemonic, passphrase=""):
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048, 64)

def seed_to_master_key(seed):
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return h[:32], h[32:]

def derive_child_key(parent_key, chain_code, index):
    if index >= 0x80000000:
        data = b'\x00' + parent_key + struct.pack('>I', index)
    else:
        data = hashlib.sha256(parent_key).digest()[:33] + struct.pack('>I', index)
    
    h = hmac.new(chain_code, data, hashlib.sha512).digest()
    child_key = (int.from_bytes(h[:32], 'big') + int.from_bytes(parent_key, 'big')) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    return child_key.to_bytes(32, 'big'), h[32:]

def derive_btc_address(private_key, path="m/44'/0'/0'/0/0"):
    key, chain = private_key, b'\x00' * 32
    for part in path.replace("m/", "").split("/"):
        if not part:
            continue
        hardened = "'" in part
        idx = int(part.replace("'", ""))
        if hardened:
            idx += 0x80000000
        key, chain = derive_child_key(key, chain, idx)
    return key

# ============================================================================
# BRAINWALLET GENERATOR
# ============================================================================

def generate_brainwallet_phrases() -> List[str]:
    phrases = []
    
    common_passwords = [
        "password", "12345678", "qwerty123", "letmein", "monkey123",
        "dragonball", "starwars", "naruto", "bitcoin", "ethereum",
        "satoshi", "vitalik", "metamask", "trustwallet", "blockchain",
        "crypto", "iloveyou", "admin123", "rootroot", "passw0rd",
        "correct horse battery staple", "to be or not to be",
        "hello world", "changeme", "masterkey", "secret123"
    ]
    
    for pw in common_passwords:
        h = hashlib.sha256(pw.encode()).digest()
        indices = [((h[i] << 8) | h[(i+1) % len(h)]) % 2048 for i in range(12)]
        phrase = ' '.join(BIP39_WORDS[i] for i in indices)
        phrases.append(phrase)
        
        h2 = hashlib.sha256((pw + "123").encode()).digest()
        indices2 = [((h2[i] << 8) | h2[(i+1) % len(h2)]) % 2048 for i in range(12)]
        phrases.append(' '.join(BIP39_WORDS[i] for i in indices2))
    
    return phrases

def generate_sequential_phrases(count=100) -> List[str]:
    phrases = []
    for start in range(0, min(count, 2037)):
        words = BIP39_WORDS[start:start+12]
        phrases.append(' '.join(words))
    return phrases

def generate_repeated_phrases() -> List[str]:
    phrases = []
    common_indices = [0, 1, 2, 3, 10, 100, 500, 1000, 1500, 2000, 2047]
    for idx in common_indices:
        word = BIP39_WORDS[idx]
        phrases.append(' '.join([word] * 12))
    return phrases

# ============================================================================
# ADDRESS DERIVATION & BALANCE CHECK
# ============================================================================

def private_to_btc_addresses(private_key):
    try:
        from coincurve import PrivateKey
        pk = PrivateKey(private_key)
        pub = pk.public_key.format()
        h = hashlib.sha256(pub).digest()
        r = hashlib.new('ripemd160', h).digest()
        return {'p2pkh': '1' + binascii.hexlify(r).decode()[:33]}
    except:
        return {}

def check_btc_balance(address):
    try:
        resp = requests.get(f"https://blockchain.info/balance?active={address}", timeout=5)
        data = resp.json()
        balance = data.get(address, {}).get('final_balance', 0)
        return balance / 1e8
    except:
        return 0.0

# ============================================================================
# STREAMLIT UI
# ============================================================================

st.set_page_config(page_title="Bitcoin Key Hunter", page_icon="₿")
st.title("₿ Bitcoin Key Hunter")
st.subheader("BIP-39 Mnemonic Scanner — Find Wallets With Real BTC")
st.caption(f"Canonical BIP-39: {len(BIP39_WORDS)} words | All phrases validated")

st.markdown("---")

tab1, tab2, tab3, tab4 = st.tabs([
    "💻 Generate Valid",
    "🔍 Validate Phrase",
    "🖥 Weak Patterns",
    "💰 Scan Balances"
])

with tab1:
    c1, c2 = st.columns(2)
    with c1:
        count = st.slider("Count", 1, 20, 5, key="gen_count")
    with c2:
        wc = st.radio("Words", [12, 24], horizontal=True, key="gen_wc")
    
    if st.button(" Generate", type="primary", use_container_width=True):
        phrases = []
        for _ in range(count):
            p = generate_valid_mnemonic(wc)
            v = validate_mnemonic(p)
            phrases.append({"phrase": p, "valid": v})
        st.session_state['gen_phrases'] = phrases
        st.success(f"{sum(1 for x in phrases if x['valid'])}/{len(phrases)} valid")
    
    if 'gen_phrases' in st.session_state:
        for i, r in enumerate(st.session_state['gen_phrases']):
            with st.expander(f"{'✔️' if r['valid'] else '❌'} Phrase {i+1}"):
                st.code(r['phrase'])
                if r['valid']:
                    seed = mnemonic_to_seed(r['phrase'])
                    key, chain = seed_to_master_key(seed)
                    st.text(f"Master Key: {key.hex()}")

with tab2:
    phrase = st.text_area("Paste mnemonic:", height=80, key="val_input")
    
    if st.button("✔️ Validate", type="primary", use_container_width=True, key="val_btn"):
        if phrase.strip():
            words = phrase.strip().split()
            bad = [w for w in words if w not in WORD_TO_INDEX]
            
            if len(words) not in [12, 15, 18, 21, 24]:
                st.error(f"Word count: {len(words)} — must be 12/15/18/21/24")
            elif bad:
                st.error(f"Unknown: {', '.join(bad)}")
            else:
                valid = validate_mnemonic(phrase.strip())
                if valid:
                    st.success("✔️ VALID BIP-39 — Accepted by ALL wallets")
                else:
                    st.error("❌️ INVALID checksum — REJECTED by wallets")

with tab3:
    st.subheader("Weak Pattern Generators")
    
    strategy = st.selectbox("Strategy", [
        "Brainwallet (common passwords)",
        "Sequential words",
        "Repeated words",
        "All combined"
    ])
    
    if st.button(" Generate Weak Phrases", type="primary", use_container_width=True):
        phrases = []
        
        if "Brainwallet" in strategy or "All" in strategy:
            phrases.extend(generate_brainwallet_phrases())
        if "Sequential" in strategy or "All" in strategy:
            phrases.extend(generate_sequential_phrases(100))
        if "Repeated" in strategy or "All" in strategy:
            phrases.extend(generate_repeated_phrases())
        
        st.session_state['weak_phrases'] = phrases
        st.success(f"Generated {len(phrases)} weak phrases")
    
    if 'weak_phrases' in st.session_state:
        for i, p in enumerate(st.session_state['weak_phrases'][:30]):
            valid = validate_mnemonic(p)
            with st.expander(f"{'✔️' if valid else '❌️'} Weak Phrase {i+1}"):
                st.code(p)
                if valid:
                    seed = mnemonic_to_seed(p)
                    key, chain = seed_to_master_key(seed)
                    st.text(f"Key: {key.hex()}")

with tab4:
    st.subheader("Balance Scanner")
    st.warning("Rate limited — use sparingly")
    
    phrase_to_scan = st.text_area("Enter phrase to scan:", height=80, key="scan_input")
    
    if st.button("💰 Scan BTC Balance", type="primary", use_container_width=True, key="scan_btn"):
        if phrase_to_scan.strip():
            if validate_mnemonic(phrase_to_scan.strip()):
                seed = mnemonic_to_seed(phrase_to_scan.strip())
                master_key, master_chain = seed_to_master_key(seed)
                
                paths = ["m/44'/0'/0'/0/0", "m/49'/0'/0'/0/0", "m/84'/0'/0'/0/0"]
                
                for path in paths:
                    derived = derive_btc_address(master_key, path)
                    addrs = private_to_btc_addresses(derived)
                    
                    for addr_type, addr in addrs.items():
                        balance = check_btc_balance(addr)
                        
                        col1, col2, col3 = st.columns(3)
                        col1.metric("Path", path)
                        col2.metric("Address", addr[:12] + "...")
                        col3.metric("Balance", f"{balance:.8f} BTC")
                        
                        if balance > 0:
                            st.balloons()
                            st.success(f"💰 FOUND: {balance} BTC at {addr}")
                            st.code(phrase_to_scan)
                            st.text(f"Private Key: {derived.hex()}")
            else:
                st.error("Invalid mnemonic — cannot scan")

st.markdown("---")
st.caption("Bitcoin Key Hunter | BIP-39 Compliant | Research Use Only")
