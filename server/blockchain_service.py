import os
from web3 import Web3

CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS")
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
SEOPLIA_RPC_URL = os.getenv("SEOPLIA_RPC_URL")

ABI = [
    {
        "inputs": [{"internalType": "bytes32", "name": "_hash", "type": "bytes32"}],
        "name": "recordDigest",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    }
]

def get_contract():
    w3 = Web3(Web3.HTTPProvider(SEOPLIA_RPC_URL))
    return w3, w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)

def record_digest_on_chain(digest_hex: str) -> str:
    # Takes idgest string from message, hashes to bytes32, submits to contract & returns transaction hash
    w3, contract = get_contract()
    account = w3.eth.account.from_kry(PRIVATE_KEY)
    
    #Convert digest string to bytes32
    digest_bytes = Web3.keccake(text=digest_hex)

    tx = contract.functions.recordDigest(digest_bytes).build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 100000,
        "gasPrice": w3.eth.gas_price,
    })

    signed = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    return receipt.transactionHash.hex()