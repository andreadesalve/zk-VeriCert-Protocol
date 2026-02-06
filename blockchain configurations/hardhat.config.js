
require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  networks: {
    hardhat: {
      chainId: 0x539, // 1337
      allowUnlimitedContractSize: true,
      gas: 2100000,
      gasPrice: 8000000000,
      accounts: {
        mnemonic: "family dress industry stage bike shrimp replace design author amateur reopen script"
      }
    }
  }
};
