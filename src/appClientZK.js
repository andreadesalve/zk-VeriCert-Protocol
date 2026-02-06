const net = require('net')
const jwtVP = require('./jwt-vp.js')
const SSIOp = require('./SSIOp.js')
const fs = require('fs').promises
const config = require('../config.json')
const { X509Certificate } = require('node:crypto')
const { performance } = require('perf_hooks')
const { ec } = require('elliptic') // ECDSA
const ecCurve1 = new ec('secp256k1')
const {ethers} = require("ethers")


const args = process.argv.slice(2)
let contractInstance = null

if(args.length > 0) {
  switch(args[0]){
    case 'VP':

      SSIOp.initGanache().then(() => {
        contractInstance = SSIOp.getContractInstance();
      });

      let clientVP = new net.Socket()
      clientVP.connect(config.server.portSSI, config.server.ipAddrSSI, () => {
        console.log('Connect to the server... ');
        clientVP.write('TLS-VP request');
      });

      //Management VP from server
      clientVP.on('data', async (data) => {
        
        let verifyVPTime = null
        let resultVP = null
        let VPsizeInKB = null
        let commName = null
        let resultCRT = null

        try {
          /*
          * ---------------------------------------------------------
          *     JWT VP VERIFICATION + PERFORMANCE (DID RESOLUTION)
          * ---------------------------------------------------------
          */
          const token = await JSON.parse(data.toString())
          console.log("Token: "+token)
          const res = await jwtVP.verifyPresentationJwtES256Perf(token)
          let serverDID = await res[0]
          resultVP = await res[1]
          verifyVPTime = await res[2]
          VPsizeInKB = await res[3]
          
          if(resultVP) {
            /*
            * --------------------------------------------------------
            *     CT VERIFICATION + PERFORMANCE (TX SMART CONTRACT)
            * --------------------------------------------------------
            */
            console.log(serverDID.split(":")[3])


            const gasEstimate = await contractInstance.estimateGas.infoCT(serverDID.split(":")[3]);
            //console.log("Estimated gas:", gasEstimate.toString());


            let start = performance.now()
            //Transaction for certificate hash and RA signature
            //console.log("Server did "+serverDID.split(":")[3])
            const tx = await contractInstance.infoCT(serverDID.split(":")[3])
            let end0 = performance.now()
           // console.log("InfoCT "+JSON.stringify(tx))
            const crtChain = res[4].TLSCertChain.split(',')
            const X509Cert = new X509Certificate(crtChain[0])
            const CertHash_BC = tx
            let CertHash_VP = "0x" + X509Cert.fingerprint256.replace(/:/g, '').toLowerCase()
            let end1 = performance.now()

            let verifyCrtTrTime = parseFloat((end1 - start).toFixed(2))
            let infoCT_Time = parseFloat((end0 - start).toFixed(2))

            //const csvRow = `${infoCT_Time},${gasEstimate.toString()}\n`
            //fs.appendFile(config.perfFiles.infoCTPerf, csvRow)
            console.log("Hash(cert) - off-chain "+CertHash_VP)
            console.log("Hash(cert) - on-chain "+CertHash_BC)
            if(CertHash_VP == CertHash_BC) {
              /*
                * ---------------------------------------------------
                *       ZK SIGNATURE VERIFICATION + PERFORMANCE
                * ---------------------------------------------------
              */
              start = performance.now()
              const tx = await contractInstance.getDproof(serverDID.split(":")[3])
               end0 = performance.now()
              let getZK = parseFloat((end0 - start).toFixed(2))
                 const gasEstimate = await contractInstance.estimateGas.getDproof(serverDID.split(":")[3]);
                          //const csvRow = `${getZK},${gasEstimate.toString()}\n`
                          //fs.appendFile(config.perfFiles.infoGETPROOFPerf, csvRow)

              const proofBc = tx[0]
              const publicSignalsBc = tx[1]
              commName = res[4].id
              const regex = /CN=([^,]+)/
              const matches = X509Cert.subject.match(regex)
              console.log("Common name "+commName)
              if(!(matches && matches.length > 1)) {
                throw new Error("NO COMMON NAME FOUND")
              }
              
              if(commName != matches[1]) {
                throw new Error("Id credential different from X509-CommonName")
              }


            const pbase64 = ethers.utils.toUtf8String(proofBc);
            // Decode base64 → JSON string
            const jsonpString = Buffer.from(pbase64, "base64").toString("utf-8");
            // Parse JSON
            const proof = JSON.parse(jsonpString);

            const psbase64 = ethers.utils.toUtf8String(publicSignalsBc);
            const jsonpsString = Buffer.from(psbase64, "base64").toString("utf-8");
            const publicSignals = JSON.parse(jsonpsString);


              //Validate ZK proof
              start = performance.now()
              console.log("prepare parameters verification ")
              //let proof = JSON.parse(res[4].proof)
              console.log("proof ")
              //let publicSignals = JSON.parse(res[4].publicSignals)
              console.log("publicSignals ")
              let v=res[4].v
              console.log("v ")
              const buf = await fs.readFile("./ZK/verification_key.json");
              const vKey = JSON.parse(buf.toString("utf8"))
              console.log("vkey ")
               console.log("Start verification ")
              let zkres = await SSIOp.verifyZKProofLocally(vKey,serverDID,v,proof,publicSignals)
              console.log("Valid proof? ", zkres);
              let end = performance.now()
              let ZKVerTime = parseFloat((end - start).toFixed(2))
              
              if(zkres) {
                /*
                * -------------------------------------------
                *       OPENSSL VERIFICATION + PERFORMANCE
                * -------------------------------------------
                */
                //Create server certificate file
                //await fs.writeFile('./certServer.pem', crtChain[0]);
    
                //Create inter CAs certificates file
                const crtIntArr = crtChain.slice(1);
                const crtIntStr = crtIntArr.join(',').replace(/,/g, "\n");
                //await fs.writeFile('./certChain.pem', crtIntStr);

                //OpenSSL certificate check
                //let start = performance.now()
                //resultCRT = await SSIOp.crtVerify()
                resultCRT='OK'
                //let end = performance.now()
                //let crtVerTime = parseFloat((end - start).toFixed(2))
                let crtVerTime =0
                //console.log("crtVerify "+resultCRT)
                //CRT size
                const crtLengthInBytes = Buffer.byteLength(crtChain[0], 'utf-8');
                const crtSizeInKB = parseFloat((crtLengthInBytes / 1024).toFixed(2));

                //Trust chain size
                const chainLengthInBytes = Buffer.byteLength(crtIntStr, 'utf-8');
                const chainSizeInKB = parseFloat((chainLengthInBytes / 1024).toFixed(2));

                //Number of inter CAs
                const numInterCA = crtIntStr.split('-----BEGIN CERTIFICATE-----').length - 1;
                
                //SSIOp.writePerf('OK', commName, verifyVPTime, resultVP, crtVerTime, resultCRT, getZK, ZKVerTime, verifyCrtTrTime, numInterCA, crtSizeInKB, chainSizeInKB, VPsizeInKB)
                const csvRow = `OK,${commName},${verifyVPTime},${resultVP},${infoCT_Time},${verifyCrtTrTime},${resultCRT},${getZK},${ZKVerTime},${numInterCA},${VPsizeInKB}\n`
                fs.appendFile(config.perfFiles.verifyVP, csvRow)
            
              } else {
                console.log('RA SIGNATURE INVALID');
                SSIOp.writePerf('ZK-INVALID', commName, verifyVPTime, resultVP, '', '', ZKVerTime, verifyCrtTrTime, '', '','', VPsizeInKB, "VP")
              }

            } else {
              console.log('CRT HASH IN VP DIFFERENT FROM CRT HASH IN BLOCKCHAIN');
              SSIOp.writePerf('CRT-TR-INVALID', commName, verifyVPTime, resultVP, infoCT_Time, '', verifyCrtTrTime,'', '','', '', VPsizeInKB, "VP")
            }
          } else {
            console.log("INVALID VP")
            SSIOp.writePerf('VP-INVALID', commName, verifyVPTime, resultVP, '','', '','', '', '', '', VPsizeInKB, "VP")
          }
        } catch (error) {
          resultCRT = false
          SSIOp.writePerf(error.message, commName, verifyVPTime, resultVP, '',resultCRT, '','', '', '', '', VPsizeInKB, "VP")
          console.error("VERIFICATION FAILURE:" + error)
        }
        clientVP.write('TLS-VP request')
      })
      break

    case 'CRT':

      let clientCRT = new net.Socket()

      clientCRT.connect(config.server.portCRT, config.server.ipAddrCRT, () => {
          console.log('Connect to the server... ');
          clientCRT.write('CRT request');
      });

      clientCRT.on('data', async (data) => {
        let commName = null
        let result = null       
        try {
          /*
           * ------------------------------------------
           *       OPENSSL VERIFICATION + PERFORMANCE
           * ------------------------------------------
          */
          const crtArray = data.toString().split(',');

          //Create server certificate file
          let X509Cert = new X509Certificate(crtArray[0])
          const regex = /CN=([^,]+)/
          const matches = X509Cert.subject.match(regex)

          if (!(matches && matches.length > 1)) {
              throw new Error("NO COMMON NAME FOUND")
          }
          commName = matches[1]
          await fs.writeFile('./certServer.pem', crtArray[0])

          //Create inter CAs certificates file
          const crtChainArr = crtArray.slice(1);
          const crtChainStr = crtChainArr.join(',').replace(/,/g, "\n");
          await fs.writeFile('./certChain.pem', crtChainStr);

          //OpenSSL certificate check
          let start = performance.now() //Start time openssl certificate check

          result = await SSIOp.crtVerify()

          let end = performance.now() //End time openssl certificate check
          let verifyCRTime = parseFloat((end - start).toFixed(2))

          //CRT size
          const crtLengthInBytes = Buffer.byteLength(crtArray[0], 'utf-8');
          const crtSizeInKB = parseFloat((crtLengthInBytes / 1024).toFixed(2));

          //Trust chain size
          const chainLengthInBytes = Buffer.byteLength(crtChainStr, 'utf-8');
          const chainSizeInKB = parseFloat((chainLengthInBytes / 1024).toFixed(2));

          //Number of inter CAs
          let numInterCA = crtChainStr.split('-----BEGIN CERTIFICATE-----').length - 1;

          SSIOp.writePerf('OK', commName, '', '', verifyCRTime, result, '', '', numInterCA, crtSizeInKB, chainSizeInKB, '', "CRT")
          
        } catch (error) {
          result = false
          SSIOp.writePerf(error.message, commName, '', '', '',result, '','', '', '', '', '', "CRT")
          console.error("CRT CHECK ERROR:" + error);
        }
        clientCRT.write('CRT request')
      });
      clientCRT.on('close', () => {
        console.log('CONNECTION CLOSED');
      });
      break   
    default:
      console.log('INVALID CLIENT TYPE')
  }
} else {
    console.log('ADD CLIENT TYPE LIKE: VP or CRT')
}