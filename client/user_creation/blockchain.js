// Blockchain digest submission — calls MessageDigest.recordDigest() on Sepolia.
// Requires environment variables:
//   SEPOLIA_RPC_URL   — HTTP RPC endpoint (e.g. Infura/Alchemy)
//   PRIVATE_KEY       — hex private key of the submitter wallet (no 0x prefix)
//   CONTRACT_ADDRESS  — deployed MessageDigest contract address

import { JsonRpcProvider, Wallet, Contract } from 'ethers';

const ABI = [
    'function recordDigest(bytes32 _hash) external returns (uint256)',
    'event DigestRecorded(uint256 indexed id, bytes32 hash, uint256 timestamp)',
];

// Submits a keccak256 digest (0x-prefixed hex string from ratchetEncrypt) to the
// MessageDigest contract. Returns the transaction hash for storage alongside the message.
export async function submitDigest(digest) {
    const rpcUrl          = process.env.SEPOLIA_RPC_URL;
    const privateKey      = process.env.PRIVATE_KEY;
    const contractAddress = process.env.CONTRACT_ADDRESS;

    if (!rpcUrl || !privateKey || !contractAddress) {
        throw new Error(
            'Blockchain submission requires SEPOLIA_RPC_URL, PRIVATE_KEY, and CONTRACT_ADDRESS env vars',
        );
    }

    const provider = new JsonRpcProvider(rpcUrl);
    const signer   = new Wallet(privateKey, provider);
    const contract = new Contract(contractAddress, ABI, signer);

    const tx      = await contract.recordDigest(digest);
    const receipt = await tx.wait();
    return receipt.hash;
}
