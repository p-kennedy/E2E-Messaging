import os
from web3 import Web3
from hexbytes import HexBytes

CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
SEPOLIA_RPC_URL = os.getenv("SEPOLIA_RPC_URL")

ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "_hash", "type": "bytes32"}],
        "name": "recordDigest",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "uint256", "name": "id", "type": "uint256"},
            {"indexed": False, "internalType": "bytes32", "name": "hash", "type": "bytes32"},
            {"indexed": False, "internalType": "uint256", "name": "timestamp", "type": "uint256"},
        ],
        "name": "DigestRecorded",
        "type": "event",
    },
]

def get_contract():
    if not SEPOLIA_RPC_URL or not PRIVATE_KEY or not CONTRACT_ADDRESS:
        raise ValueError("Missing required env vars: SEOPLIA_RPC_URL, PRIVATE_KEY, CONTRACT_ADDRESS")

    w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL))
    checksum_address = Web3.to_checksum_address(CONTRACT_ADDRESS)
    return w3, w3.eth.contract(address=checksum_address, abi=ABI)

def record_digest_on_chain(digest_hex: str) -> str:
    print(f"[Blockchain] Attempting to anchor digest: {digest_hex}")
    print(f"[Blockchain] RPC URL: {SEPOLIA_RPC_URL}")
    print(f"[Blockchain] Contract: {CONTRACT_ADDRESS}")

    if not SEPOLIA_RPC_URL or not PRIVATE_KEY or not CONTRACT_ADDRESS:
        raise ValueError("Missing required env vars")

    print("[Blockchain] Connecting to provider...")
    w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL))
    
    print(f"[Blockchain] Connected: {w3.is_connected()}")
    
    checksum_address = Web3.to_checksum_address(CONTRACT_ADDRESS)
    contract = w3.eth.contract(address=checksum_address, abi=ABI)
    
    print("[Blockchain] Loading account...")
    account = w3.eth.account.from_key(PRIVATE_KEY)
    print(f"[Blockchain] Account: {account.address}")

    digest_bytes = bytes.fromhex(digest_hex.removeprefix("0x"))
    
    print("[Blockchain] Building transaction...")
    tx = contract.functions.recordDigest(digest_bytes).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 200000,
        "gasPrice": w3.eth.gas_price,
    })

    print("[Blockchain] Signing transaction...")
    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    
    print("[Blockchain] Sending transaction...")
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    
    print(f"[Blockchain] Waiting for receipt... tx: {tx_hash.hex()}")
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    return receipt["transactionHash"].hex()


def get_record_by_tx(tx_hash: str) -> dict:
    print(f"[Blockchain] Looking up tx: {tx_hash}")
    w3, contract = get_contract()

    # Normalise — add 0x prefix if missing
    if not tx_hash.startswith("0x"):
        tx_hash = "0x" + tx_hash

    receipt = w3.eth.get_transaction_receipt(HexBytes(tx_hash))
    if receipt is None:
        raise ValueError("Transaction not found")

    # Parse the DigestRecorded event from the logs
    logs = contract.events.DigestRecorded().process_receipt(receipt)
    if not logs:
        raise ValueError("No DigestRecorded event found in transaction")

    event = logs[0]
    return {
        "on_chain_hash": "0x" + event["args"]["hash"].hex(),
        "timestamp": event["args"]["timestamp"],
        "block": receipt["blockNumber"],
    }