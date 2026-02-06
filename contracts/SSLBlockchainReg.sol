// SPDX-License-Identifier: MIT 
pragma solidity >=0.4.22 <0.9.0;

//import "./Groth16Verifier.sol";

contract SSLBlockchainReg {
    struct Entry {
        address ethAddr;
        bytes id;
        bytes secretHash;
        bytes certHash;
        bytes dsZK;
        bytes publicSignals;
        address revkAddr;
    }

    //Groth16Verifier public verifier = new Groth16Verifier();
    address public owner;

    bytes public circuitWasmCID;
    bytes public provingKeyCID;
    bytes public verificationKeyCID;



    mapping (bytes => Entry) public registry;
    mapping (address => bool) private isValueExist_Addr;
    mapping (bytes => bool) private isValueExist_ID;
    mapping (bytes => bool) private isValueExist_Secret;

    event updCertHash(
        bytes identity,
        bytes newCertHash
    );

    event updDsZK(
        bytes identity,
        bytes newZkProof
    );

    event rvkDID(
        address ethAddr,
        bytes identity
    );

    event zkCircuitUpdated(
        bytes wasmCID,
        bytes zkeyCID,
        bytes vkeyCID
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT AUTHORIZED");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function newDID(bytes memory identity, bytes memory secretHash, address revkAddr) public{
        require(!isValueExist_Addr[msg.sender], "ADDRESS ALREADY REGISTERED");
        require(!isValueExist_ID[identity],"IDENTITY ALREADY REGISTERED");
        //require(!isValueExist_Secret[secretHash], "SECRET HASH ALREADY USED");
        require(!isValueExist_Addr[revkAddr], "REVOKE ADDRESS ALREADY REGISTERED");

        isValueExist_Addr[msg.sender] = true;
        isValueExist_ID[identity] = true;
        isValueExist_Addr[revkAddr] = true;
        isValueExist_Secret[secretHash] = true;

        Entry memory entry = Entry(msg.sender, identity, secretHash, hex"00", hex"00", hex"00", revkAddr);
        registry[identity] = entry;
    }

    //If the event returns registry[identity].id 0x0 means a revoked did
    function resolutionDID(bytes memory identity) public view returns(bytes memory, address){
        require(isValueExist_ID[identity], "UNREGISTERED IDENTITY");
        return(registry[identity].id, registry[identity].ethAddr);
    }

    //If the event returns registry[identity].id 0x0 means a revoked did
    function infoCT(bytes memory identity) public view returns(bytes memory){
        require(isValueExist_ID[identity], "UNREGISTERED IDENTITY");
        return registry[identity].certHash;
    }

    function getDproof(bytes memory identity) public view returns (bytes memory, bytes memory)
    {
        require(isValueExist_ID[identity], "UNREGISTERED IDENTITY");
        return(registry[identity].dsZK, registry[identity].publicSignals);
    }

    //It can be called to update both certificate hash and dsRA or only one of these two values at time.
    function updateEntry(bytes memory identity, bytes memory newCertHash, bytes memory newdsZK, bytes memory newpublicSignals ) public {
        require(msg.sender == registry[identity].ethAddr, "NO ACCESS RIGHT");
    
        if(bytes(newCertHash).length > 0) {
            registry[identity].certHash = newCertHash;
            emit updCertHash(identity, registry[identity].certHash);
        }

        if(bytes(newdsZK).length > 0 && bytes(newpublicSignals).length > 0) {
            registry[identity].dsZK = newdsZK;
            registry[identity].publicSignals = newpublicSignals;
            emit updDsZK(identity, registry[identity].dsZK);
        }
    }

    function revokeDID(bytes memory identity, bytes memory secret) public {
        require(isValueExist_ID[identity],"UNREGISTERED IDENTITY");
        require(msg.sender == registry[identity].revkAddr, "INVALID SIGNER FOR REVOKE TX");
        require(keccak256(abi.encodePacked(secret)) == bytes32(registry[identity].secretHash), "INVALID SECRET");

        delete(registry[identity]);

        emit rvkDID(msg.sender, identity);
    }


    function setZkCircuitFiles(bytes memory wasmCID, bytes memory zkeyCID, bytes memory vkeyCID) public onlyOwner {
        circuitWasmCID = wasmCID;
        provingKeyCID = zkeyCID;
        verificationKeyCID = vkeyCID;
        emit zkCircuitUpdated(wasmCID, zkeyCID, vkeyCID);
    }


    function getZkCircuitFiles() public view returns (bytes memory, bytes memory, bytes memory)
    {
        return (circuitWasmCID, provingKeyCID, verificationKeyCID);
    }


}
