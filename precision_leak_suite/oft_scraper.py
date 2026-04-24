import requests
import json

def get_oft_targets():
    print("[*] QuantumBlue: Fetching LayerZero OFT Deployment List...")
    url = "https://metadata.layerzero-api.com/v1/metadata/experiment/ofts/list"
    
    try:
        response = requests.get(url)
        data = response.json()
        
        targets = []
        for entry in data:
            # We filter for EVM chains where sUSDe style bugs are most common
            targets.append({
                "symbol": entry.get("symbol"),
                "address": entry.get("address"),
                "chain": entry.get("chainName")
            })
        
        with open("oft_targets.json", "w") as f:
            json.dump(targets, f, indent=4)
        
        print(f"[+] Successfully indexed {len(targets)} potential targets.")
    except Exception as e:
        print(f"[!] Error fetching OFTs: {e}")

if __name__ == "__main__":
    get_oft_targets()
