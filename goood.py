import requests
import base64
import hashlib
import threading
import struct
import hmac
from ecdsa import SECP256k1, SigningKey
import base58
import bech32
from mnemonic import Mnemonic
from bs4 import BeautifulSoup
from colorama import Fore
from concurrent.futures import ThreadPoolExecutor

# Helper functions
def hmac_sha512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()

def hash160(data):
    sha256 = hashlib.sha256(data).digest()
    return hashlib.new('ripemd160', sha256).digest()

def derive_child_key(parent_key, parent_chain_code, index):
    BIP32_HARDEN = 0x80000000
    data = struct.pack('>L', index)
    if index & BIP32_HARDEN:
        data = b'\x00' + parent_key + data
    else:
        pub_key = SigningKey.from_string(parent_key, curve=SECP256k1).verifying_key.to_string()
        pub_key = b'\x02' + pub_key[:32] if pub_key[-1] % 2 == 0 else b'\x03' + pub_key[:32]
        data = pub_key + data

    I = hmac_sha512(parent_chain_code, data)
    child_key = (int.from_bytes(I[:32], 'big') + int.from_bytes(parent_key, 'big')) % SECP256k1.order
    return child_key.to_bytes(32, 'big'), I[32:]

def generate_mnemonic_and_address(mnemonic_phrase):
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic_phrase)
    I = hmac_sha512(b'Bitcoin seed', seed)
    master_secret, master_chain_code = I[:32], I[32:]

    bip84_path = [84 + 0x80000000, 0 + 0x80000000, 0 + 0x80000000, 0, 0]
    key, chain_code = master_secret, master_chain_code
    for idx in bip84_path:
        key, chain_code = derive_child_key(key, chain_code, idx)

    pub_key = SigningKey.from_string(key, curve=SECP256k1).verifying_key.to_string()
    pub_key = b'\x02' + pub_key[:32] if pub_key[-1] % 2 == 0 else b'\x03' + pub_key[:32]
    pub_key_hash = hash160(pub_key)
    address = bech32.encode('bc', 0, pub_key_hash)

    response = requests.get(f"https://blockchain.info/balance?active={address}")
    balance_data = response.json().get(address, {})
    bal, tx, tot = balance_data.get("final_balance", 0), balance_data.get("n_tx", 0), balance_data.get("total_received", 0)

    result = f"{Fore.GREEN}•Mnemonic: {mnemonic_phrase}\n•Address: {address}\n•Balance: {bal}\n•Total Transactions: {tx}\n•Total Received: {tot}"
    print(result)

    if bal > 0 or tx > 0:
        with open("realbtc.txt", "a") as file:
            file.write("\n" + result)

def get_random_image():
    mnemo = Mnemonic("english")
    search_term = mnemo.generate()
    url = f"https://www.google.com/search?q={search_term}&tbm=isch"

    headers = {"User-Agent": "Mozilla/5.0"}
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    return [img["src"] for img in soup.find_all("img") if img.get("src") and "http" in img["src"]]

def image_to_base64(image_url):
    response = requests.get(image_url)
    return base64.b64encode(response.content).decode()

def hash_sha256(base64_string):
    return hashlib.sha256(base64_string.encode()).hexdigest()

def hash_to_mnemonic(hash_value):
    entropy = bytes.fromhex(hash_value)
    return Mnemonic("english").to_mnemonic(entropy)

def process_image(image_url):
    try:
        base64_string = image_to_base64(image_url)
        sha256_hash = hash_sha256(base64_string)
        mnemonic = hash_to_mnemonic(sha256_hash)
        generate_mnemonic_and_address(mnemonic)
    except Exception as e:
        print(f"Error processing image {image_url}: {e}")

def main():
    while True:
        try:
            images = get_random_image()
            with ThreadPoolExecutor(max_workers=55) as executor:
                executor.map(process_image, images)
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()
