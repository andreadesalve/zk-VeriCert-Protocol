# zk-VeriCert
## Overview

**zk-VeriCert** explores the integration of **Self-Sovereign Identity (SSI)** principles into the **Public Key Infrastructure (PKI)** to enhance security, transparency, and privacy in digital identity management.

The protocol combines:
- **Decentralized Identifiers (DIDs)**
- **Zero-Knowledge Proof**
- **Smart Contracts**
- **Blockchain Technology**

to provide a decentralized and auditable framework for managing digital identities and certificates, with a specific focus on **Certificate Transparency** and **Verifiable Presentations (VPs)** during the TLS handshake.

## Architecture & Concepts

- **DIDs** follow the W3C specification in the format:  
  `did:ethr:<identifier>`
- **DID lifecycle and resolution** are handled via:
  - A custom DID resolver based on `did-resolver`
  - Smart contract `SSLBlockchainReg.sol`
- **Blockchain layer**:
  - Ethereum-compatible
  - Used to ensure transparency and integrity of certificate-related operations
- **Performance evaluation**:
  - Measurement of VP exchange and verification overhead during TLS handshakes between client and server

## Technologies Used

- JavaScript
- Solidity
- Node.js (tested with **Node.js 17**)
- Truffle
- Ganache
- Ethereum
- Decentralized Identity Foundation (DIF) libraries:
  - `did-resolver`
  - `did-jwt`
  - `did-jwt-vc`

## Prerequisites

Make sure the following tools are installed:

- Node.js v17
- npm
- Truffle
- Ganache

Install project dependencies:

```bash
npm install
```
## Installation & Local Testing
This project is intended for local experimentation and performance evaluation.
- Start a Local Blockchain
  - Launch a Ganache instance.
- Deploy Smart Contracts
  - Update deployment configuration:
    ```bash
    workdir/truffle-config.js
    ```
  - Deploy the contracts:
    ```bash
      truffle migrate
    ```
- Configure the Application
  - Edit the configuration file:
    ```bash
      workdir/config.json
    ```
  - Update:
    Smart contract address
    Mnemonic
    Provider URL
    Paths for performance CSV files under perfFiles
- Run the Experiment
Open two separate terminals.
  - Terminal 1 – Server:
    ```bash
    node ./scr/appServerZK.js VP
    ```
  - Terminal 2 – Client:
    ```bash
    node ./scr/appClientZK.js VP
    ```
The scripts simulate VP exchange during the TLS handshake and store performance metrics in CSV format.

## Performance Metrics
The following metrics are collected:
- VP generation time
- VP verification time
- End-to-end TLS handshake latency
- Cryptographic operation overhead
- Communication delay
Results are saved as CSV files for offline analysis.



## License
This project is licensed under the MIT License.
See the `LICENSE` file for more information.

