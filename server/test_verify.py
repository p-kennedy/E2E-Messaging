"""
Quick end-to-end test for the /verify page.

Run with the server already running:
    python test_verify.py

It will:
  1. Check the blockchain connection and wallet balance
  2. Register two throwaway users
  3. Send a test message (with the correct keccak256 digest)
  4. Poll until the blockchain tx hash is written to the DB (up to 90 s)
  5. Print the plaintext to paste into http://127.0.0.1:8000/verify
"""

import os
import sys
import time
import uuid
import requests
from pathlib import Path
from dotenv import load_dotenv
from web3 import Web3

# Load the same .env the server uses (one level up from server/)
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

BASE      = "http://127.0.0.1:8000"
PLAINTEXT = "test message for blockchain verification"


def check_blockchain():
    rpc_url          = os.getenv("SEPOLIA_RPC_URL")
    private_key      = os.getenv("PRIVATE_KEY")
    contract_address = os.getenv("CONTRACT_ADDRESS")

    missing = [k for k, v in {
        "SEPOLIA_RPC_URL":  rpc_url,
        "PRIVATE_KEY":      private_key,
        "CONTRACT_ADDRESS": contract_address,
    }.items() if not v]
    if missing:
        print(f"❌ Missing env vars: {', '.join(missing)}")
        sys.exit(1)

    print("Connecting to Sepolia...")
    w3 = Web3(Web3.HTTPProvider(rpc_url))
    if not w3.is_connected():
        print("❌ Cannot connect to Sepolia RPC — check SEPOLIA_RPC_URL and your internet connection")
        sys.exit(1)
    print(f"   Connected  (chain id: {w3.eth.chain_id})")

    account = w3.eth.account.from_key(private_key)
    balance = w3.eth.get_balance(account.address)
    eth     = w3.from_wei(balance, "ether")
    print(f"   Wallet     {account.address}")
    print(f"   Balance    {eth:.6f} ETH")
    if balance == 0:
        print("❌ Wallet has 0 ETH on Sepolia — fund it at https://sepoliafaucet.com")
        sys.exit(1)

    code = w3.eth.get_code(Web3.to_checksum_address(contract_address))
    if code in (b"", b"0x"):
        print(f"❌ No contract found at {contract_address} on Sepolia")
        sys.exit(1)
    print(f"   Contract   {contract_address}  ✓")
    print()


def main():
    # ── 0. Blockchain preflight ────────────────────────────────────────────────
    check_blockchain()

    suffix   = uuid.uuid4().hex[:8]
    sender   = f"sender_{suffix}"
    receiver = f"receiver_{suffix}"
    password = "testpassword123"

    # ── 1. Register two users ──────────────────────────────────────────────────
    for username in (sender, receiver):
        r = requests.post(f"{BASE}/api/auth/register", json={
            "username":   username,
            "password":   password,
            "public_key": "{}",
        })
        if r.status_code not in (201, 409):
            print(f"Register failed ({r.status_code}): {r.text}")
            sys.exit(1)
        print(f"Registered {username}")

    # ── 2. Login as sender ─────────────────────────────────────────────────────
    r = requests.post(f"{BASE}/api/auth/login", json={"username": sender, "password": password})
    r.raise_for_status()
    token   = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"Logged in as {sender}")

    # ── 3. Compute keccak256 digest (same encoding as verify.html) ─────────────
    # verify.html: ethers.keccak256(new TextEncoder().encode(content))
    # Web3.keccak(text=s) = keccak256 of UTF-8 bytes — identical result.
    digest = "0x" + Web3.keccak(text=PLAINTEXT).hex()
    print(f"Digest:  {digest}")

    # ── 4. Send the message ────────────────────────────────────────────────────
    r = requests.post(f"{BASE}/api/messages", headers=headers, json={
        "recipient":  receiver,
        "ciphertext": "test-ciphertext",
        "nonce":      "test-nonce",
        "header":     "{}",
        "signature":  "test-signature",
        "digest":     digest,
    })
    if r.status_code != 201:
        print(f"Send failed ({r.status_code}): {r.text}")
        sys.exit(1)
    print("Message sent — waiting for blockchain anchoring (usually 30–60 s)...")

    # ── 5. Poll /api/verify/by-content until the tx hash is available ──────────
    deadline = time.time() + 180
    while time.time() < deadline:
        r = requests.get(f"{BASE}/api/verify/by-content", params={"digest": digest})
        if r.status_code == 200:
            data = r.json()
            print("\n✅ Anchored!")
            print(f"   tx hash  : {data['tx_hash']}")
            print(f"   block    : {data['block']}")
            print(f"   timestamp: {data['timestamp']}")
            break
        elif r.status_code == 404:
            print("   still pending...", flush=True)
            time.sleep(5)
        else:
            print(f"Unexpected response ({r.status_code}): {r.text}")
            sys.exit(1)
    else:
        print("❌ Timed out — check the server terminal for a '[Blockchain] Failed to anchor' error")
        sys.exit(1)

    # ── 6. Instructions ────────────────────────────────────────────────────────
    print("\n─────────────────────────────────────────────────────")
    print("Open your browser and go to:")
    print(f"  http://127.0.0.1:8000/verify")
    print("\nPaste this into the 'Original Message Content' box:")
    print(f"  {PLAINTEXT}")
    print("\nClick 'Verify Message' — you should see a green PASS.")
    print("─────────────────────────────────────────────────────")


if __name__ == "__main__":
    main()
