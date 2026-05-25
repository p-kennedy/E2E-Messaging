import hre from "hardhat";

async function main(): Promise<void> {
  console.log("Deploying MessageDigest contract...");

  const MessageDigest = await hre.ethers.getContractFactory("MessageDigest");
  const contract = await MessageDigest.deploy();

  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("MessageDigest deployed to:", address);
  console.log("Save this address — you will need it for the backend and verification page.");
}

main().catch((error: Error) => {
  console.error(error);
  process.exitCode = 1;
});