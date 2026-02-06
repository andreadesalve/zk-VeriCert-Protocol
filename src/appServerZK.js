const net = require('net')
const SSIOp = require('./SSIOp.js');
const jwtVP = require('./jwt-vp.js')
const fs = require('fs')
const fss = require('fs').promises
const sqlite3 = require('sqlite3').verbose()
const { X509Certificate } = require('node:crypto');
const {ethers} = require("ethers")
const confServer = require('../config.json').server
const config = require('../config.json')
const args = process.argv.slice(2);

const SSIProtOptions = {
  host: confServer.ipAddrSSI,
  port: confServer.portSSI
}
const CrtOptions = {
  host: confServer.ipAddrCRT,
  port: confServer.portCRT
}

const arrDomains = Array.from(fs.readFileSync(confServer.domainsFile, 'utf8').split('\n'))

if(args.length > 0) {
  switch (args[0]) { 
    case 'VP':
      /*
        * ----------------------------------------------------------------------------------
        * 1. DID GENERATION, NEW ENTRY IN BLOCKCHAIN REG, INFO PUBLISHING
        * ----------------------------------------------------------------------------------
        * Provider, contract, wallets initialization: SSIOp.wallets[] is an array
        * of all truffle's wallet given a local blockchain of ganache. The SSIOp.wallets[0]
        * is the publisher of the smart contract. The SSIOp.wallets[1] is the account
        * ethereum of this server.
      */
      let indexVP = 0
      let indexAV= 0
      let secretArr = []; //Array with secret and secretHash
      let serverDID = null;
      let jwt = null;

      (async () => {
        await SSIOp.initGanache()
        //await SSIOp.initSepolia()

        serverWallet = await SSIOp.getWallet(1) //Main wallet for server
        serverRevkWallet = await SSIOp.getWallet(2) // Recovery wallet for server

        //systemOwnerWallet = await SSIOp.getWallet(0)
        //await SSIOp.updateZk(systemOwnerWallet,"QmPek9gJ9nyZr4omqJoghUw2xcf1b5w6YYUiHZ88fuA3Qb","QmPek9gJ9nyZr4omqJoghUw2xcf1b5w6YYUiHZ88fuA3Qb","QmPek9gJ9nyZr4omqJoghUw2xcf1b5w6YYUiHZ88fuA3Qb");


        //New secret value for server

        secretArr = await SSIOp.getSecret(confServer.secretPath)

        //Registry subscription by the server
        serverDID = await SSIOp.createDID(serverWallet, serverRevkWallet)

        for (let i = 0; i < 0; i++) {
          const myZKsecret="abcdefghilmnopqrstuvz123456789";
                  const myDID=serverDID.did;
                  let start = performance.now()
                  const hashedSec=SSIOp.getDNSTXTSecret(myZKsecret,myDID);
                  let end= performance.now()
                  let dnsTxtCreationTime = parseFloat((end - start).toFixed(2))
                  console.log("DID Server: "+myDID)
                  console.log("Zk secret: "+myZKsecret)
                  console.log("Secret: "+secretArr[1])
                  console.log("DNS TXT: "+hashedSec)
                  start = performance.now()
                  SSIOp.generateWitness(myZKsecret,myDID,hashedSec);
                  end= performance.now()
                   let witnessCreationTime = parseFloat((end - start).toFixed(2))
                   start = performance.now()
                  const proofResult=await SSIOp.generateZKProof("./serverData/circuit_final.zkey","./serverData/witness.wtns");
                  end= performance.now()
                  let zkProofCreationTime = parseFloat((end - start).toFixed(2))
                  const proofLengthInBytes = Buffer.byteLength(JSON.stringify(proofResult.proof), 'utf-8');
                  const proofSizeInKB = parseFloat((proofLengthInBytes / 1024).toFixed(2));
                  const publicSignalsLengthInBytes = Buffer.byteLength(JSON.stringify(proofResult.publicSignals), 'utf-8');
                  const publicSignalsSizeInKB = parseFloat((publicSignalsLengthInBytes / 1024).toFixed(2));
                  let witnessSizeInBytes=0
                  try {
                    const stats = fs.statSync('./serverData/witness.wtns')
                    witnessSizeInBytes = stats.size
                  } catch (err) {
                    console.log(err)
                  }
                  const witnessSizeInKB = parseFloat((witnessSizeInBytes / 1024).toFixed(2));
                  console.log("ZK Poof generated")
                  const csvRow = `${dnsTxtCreationTime},${witnessCreationTime},${witnessSizeInKB},${zkProofCreationTime},${proofSizeInKB},${publicSignalsSizeInKB}\n`
                  fss.appendFile(config.perfFiles.createZK, csvRow)
        }

        const myZKsecret="abcdefghilmnopqrstuvz123456789";
        const myDID=serverDID.did;
        let start = performance.now()
        const hashedSec=SSIOp.getDNSTXTSecret(myZKsecret,myDID);
        let end= performance.now()
        let dnsTxtCreationTime = parseFloat((end - start).toFixed(2))
        console.log("DID Server: "+myDID)
        console.log("Zk secret: "+myZKsecret)
        console.log("Secret: "+secretArr[1])
        console.log("DNS TXT: "+hashedSec)
        start = performance.now()
        SSIOp.generateWitness(myZKsecret,myDID,hashedSec);
        end= performance.now()
         let witnessCreationTime = parseFloat((end - start).toFixed(2))
         start = performance.now()
        const proofResult=await SSIOp.generateZKProof("./serverData/circuit_final.zkey","./serverData/witness.wtns");
        end= performance.now()
        let zkProofCreationTime = parseFloat((end - start).toFixed(2))
        const proofLengthInBytes = Buffer.byteLength(JSON.stringify(proofResult.proof), 'utf-8');
        const proofSizeInKB = parseFloat((proofLengthInBytes / 1024).toFixed(2));
        const publicSignalsLengthInBytes = Buffer.byteLength(JSON.stringify(proofResult.publicSignals), 'utf-8');
        const publicSignalsSizeInKB = parseFloat((publicSignalsLengthInBytes / 1024).toFixed(2));
        let witnessSizeInBytes=0
        try {
          const stats = fs.statSync('./serverData/witness.wtns')
          witnessSizeInBytes = stats.size
        } catch (err) {
          console.log(err)
        }
        const witnessSizeInKB = parseFloat((witnessSizeInBytes / 1024).toFixed(2));
        console.log("ZK Poof generated")
        //const csvRow = `${dnsTxtCreationTime},${witnessCreationTime},${witnessSizeInKB},${zkProofCreationTime},${proofSizeInKB},${publicSignalsSizeInKB}\n`
        //fss.appendFile(config.perfFiles.createZK, csvRow)
        //console.log(serverDID)
        await SSIOp.newEntry(serverDID, secretArr[1])
        console.log("New Entry created")
        console.log(arrDomains)
        const serverVP = net.createServer(async (socket) => {

          console.log('Client connected:', socket.remoteAddress, socket.remotePort)
                          
          //Listening client reqs
          socket.on('data', (async data => {

            if(data.toString() == 'TLS-VP request') {
             //console.log(arrDomains)
              console.log(arrDomains[indexVP] + " VP sent to the client...")
              try {

                //Select domain from the DB ---> only for testing
                let X509CertChain = await sendCrtData(indexVP)
                console.log("X509CertChain: "+X509CertChain)
                let X509Cert = new X509Certificate(X509CertChain.split(",")[0])
                
                const regex = /CN=([^,]+)/
                const matches = X509Cert.subject.match(regex)
                const commonName = matches[1]

                if (!(matches && matches.length > 1)) {
                  throw new Error("NO COMMON NAME FOUND")
                }


                
                //Publishing certificate info, RA singature and authentication key.
                //const vpPayload = jwtVP.createVPayload(serverDID, X509CertChain, commonName, proofResult.proof,proofResult.publicSignals,hashedSec)
                const vpPayload = jwtVP.createVPayload(serverDID, X509CertChain, commonName, hashedSec)
                console.log(JSON.stringify(vpPayload))
                //Entry update with necessary info
                const hashCert = "0x" + X509Cert.fingerprint256.replace(/:/g, '').toLowerCase();
                await SSIOp.updateEntry("CERT", serverDID, hashCert, '', '')

                proofResult.proof,proofResult.publicSignals
                // Convert to JSON string
                const jsonString = JSON.stringify(proofResult.proof);
                // Encode JSON string → base64
                const base64 = Buffer.from(jsonString, "utf-8").toString("base64");
                // Convert base64 → bytes for Solidity
                const bytesProofData = ethers.utils.toUtf8Bytes(base64);
                const jsonPsString = JSON.stringify(proofResult.publicSignals);
                const psbase64 = Buffer.from(jsonPsString, "utf-8").toString("base64");
                const bytesPsData = ethers.utils.toUtf8Bytes(psbase64);
                await SSIOp.updateEntry("ZK_SIGNATURE", serverDID, '', bytesProofData, bytesPsData)
                console.log("Hash(cert) "+hashCert)
                
                //JWT generation - PERFORMANCE INCLUDED
                jwt = await jwtVP.createPresentationJwtES256Perf(vpPayload, serverDID)
              } catch (error) {
                console.error('VP GENERATION ERROR:', error)
              }
              
              socket.write(JSON.stringify(jwt))

              indexAV = indexAV + 1
              if(indexAV >= 10) {
                indexVP = indexVP + 1
                indexAV = 0
              }
              
              if(indexVP >= arrDomains.length){
                socket.end()
              }
                
            } else {
              socket.write('INVALID REQUEST TO VP-SERVER')
            }
          }))
          //Listening client closes
          socket.on('close', () => {
            console.log('CLIENT DISCONNECTED:', socket.remoteAddress, socket.remotePort)
          })
          //Listening client errors
          socket.on('error', (error) => {
            console.error('CONNECTION ERROR:', error)
          })
        }).listen(SSIProtOptions, () => {
          console.log(`Server listening on ${SSIProtOptions.port}:${SSIProtOptions.host}...\n\n`)
        })
        serverVP.on('error', (error) => {
          console.error('SERVER ERROR:', error)
        })
      })();
      break

    case 'CRT':
      let indexCRT = 0;
      let indAV2 = 0;
      const serverCRT = net.createServer((socket) => {
        console.log('CLIENT CONNECTED:', socket.remoteAddress, socket.remotePort);
        
        // Listening client reqs
        socket.on('data', async (data) => {
          if(data.toString() == 'CRT request') {
            console.log(`${arrDomains[indexCRT]} certificate sent to the client...`)
            let crtJSON = await sendCrtData(indexCRT)
            socket.write(crtJSON)

            indAV2 = indAV2 + 1
            if(indAV2 >= 10) {
              indexCRT = indexCRT + 1
              indAV2 = 0
            }
            
            if(indexCRT >= arrDomains.length){
              socket.end()
            }


          } else {
            socket.write('INVALID REQUEST TO THE CRT-SERVER')
          }
        });

        // Listening client closes
        socket.on('close', () => {
          console.log('Client disconnected:', socket.remoteAddress, socket.remotePort);
        });
      }).listen(CrtOptions, () => {
        console.log(`Server listening on ${CrtOptions.port}:${CrtOptions.host}...\n\n`);
      });
      break
    
    default:
      console.log('INVALID SERVER TYPE')
    }
} else {
  console.log('ADD SERVER TYPE LIKE: VP or CRT')
}

async function querySQL(domain) {
  let certificates = []
  const db = new sqlite3.Database('./test/certificates.db')
  return new Promise((resolve, reject) => {
    db.serialize(() => {
      db.each(
        "SELECT * FROM certificates WHERE domain = ?",
        [domain],
        (err, row) => {
          if (err) {
            console.log(err)
          }
          certificates.push(row.certificate)
        },
        () => {
          resolve(certificates)
          db.close()
        }
      );
    });
  })
}

async function sendCrtData(index) {
  try {
    return new Promise(async resolve => {
      const crtChain = await querySQL(arrDomains[index]);
      const crtChainStr = crtChain.toString();
      resolve(crtChainStr)
    })
  } catch(error) {
    console.error(error);
  }
}




