import aiohttp
import asyncio
from typing import Dict, List
import time

class MultiChainScanner:
    def __init__(self):
        self.session = None
        self.scanned = 0
        self.hits = []
    
    async def _init(self):
        if self.session is None:
            self.session = aiohttp.ClientSession()
    
    async def check_btc(self, addr: str) -> float:
        await self._init()
        try:
            url = f"https://blockchain.info/balance?active={addr}"
            async with self.session.get(url, timeout=10) as r:
                data = await r.json()
                return data.get(addr, {}).get('final_balance', 0) / 1e8
        except:
            return 0.0
    
    async def check_eth_compatible(self, addr: str, api_url: str) -> float:
        await self._init()
        try:
            async with self.session.get(
                f"{api_url}?module=account&action=balance&address={addr}&tag=latest",
                timeout=10
            ) as r:
                data = await r.json()
                return int(data.get('result', 0)) / 1e18
        except:
            return 0.0
    
    async def scan(self, privkey: str, btc_addr: str = "",
                   eth_addr: str = "", trx_addr: str = "") -> List[Dict]:
        tasks = []
        labels = []
        
        if btc_addr:
            tasks.append(self.check_btc(btc_addr))
            labels.append(('BTC', btc_addr))
        if eth_addr:
            tasks.append(self.check_eth_compatible(eth_addr, "https://api.etherscan.io/api"))
            labels.append(('ETH', eth_addr))
            tasks.append(self.check_eth_compatible(eth_addr, "https://api.bscscan.com/api"))
            labels.append(('BSC', eth_addr))
            tasks.append(self.check_eth_compatible(eth_addr, "https://api.polygonscan.com/api"))
            labels.append(('MATIC', eth_addr))
        
        balances = await asyncio.gather(*tasks, return_exceptions=True)
        
        hits = []
        for (coin, addr), bal in zip(labels, balances):
            self.scanned += 1
            if isinstance(bal, (int, float)) and bal > 0:
                hit = {
                    'private_key': privkey,
                    'coin': coin,
                    'address': addr,
                    'balance': bal,
                    'timestamp': time.time()
                }
                self.hits.append(hit)
                hits.append(hit)
        
        return hits
    
    async def close(self):
        if self.session:
            await self.session.close()
