BIP39_WORDLIST_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt"

SUPPORTED_CHAINS = {
    'BTC': {
        'derivation': "m/44'/0'/0'/0/0",
        'api_balance': 'https://blockchain.info/balance?active={address}',
        'api_utxo': 'https://blockchain.info/unspent?active={address}',
        'api_broadcast': 'https://blockchain.info/pushtx',
        'unit_divisor': 1e8
    },
    'ETH': {
        'derivation': "m/44'/60'/0'/0/0",
        'rpc': 'https://mainnet.infura.io/v3/',
        'chain_id': 1,
        'unit_divisor': 1e18
    },
    'BSC': {
        'derivation': "m/44'/60'/0'/0/0",
        'rpc': 'https://bsc-dataseed.binance.org/',
        'chain_id': 56,
        'unit_divisor': 1e18
    },
    'TRX': {
        'derivation': "m/44'/195'/0'/0/0",
        'api': 'https://api.trongrid.io/v1/accounts/{address}',
        'unit_divisor': 1e6
    },
    'MATIC': {
        'derivation': "m/44'/60'/0'/0/0",
        'rpc': 'https://polygon-rpc.com/',
        'chain_id': 137,
        'unit_divisor': 1e18
    },
    'AVAX': {
        'derivation': "m/44'/60'/0'/0/0",
        'rpc': 'https://api.avax.network/ext/bc/C/rpc',
        'chain_id': 43114,
        'unit_divisor': 1e18
    },
    'FTM': {
        'derivation': "m/44'/60'/0'/0/0",
        'rpc': 'https://rpc.ftm.tools/',
        'chain_id': 250,
        'unit_divisor': 1e18
    },
    'SOL': {
        'derivation': "m/44'/501'/0'/0'",
        'rpc': 'https://api.mainnet-beta.solana.com',
        'unit_divisor': 1e9
    }
}
