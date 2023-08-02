const express = require("express");
const app = express();
var eenv = require('dotenv').config()
const port = process.env.PORT || 3001;
const mongoose = require("mongoose");
const Data = require('./class')
const User = require('./UserCS')
var dburi = process.env.dburi
//const dbcs = `mongodb+srv://broker:wGokfsvMGnFW5DY7@cluster0.kkxdm.mongodb.net/APT?retryWrites=true`
const dbcs = `mongodb+srv://broker:wGokfsvMGnFW5DY7@cluster0.kkxdm.mongodb.net/APT?retryWrites=true&w=majority?directConnection=true`
const crypto = require('crypto');
const https = require('https');
const cors = require('cors');



/**
 * App CORS policy definition. This *** MUST be before *** all external functions and endpoints
 */
var acceptedUrl = process.env.aurl
app.use(function (req, res, next) {
      console.log('accepted Url:')
      console.log(acceptedUrl)
      res.header("Access-Control-Allow-Origin", acceptedUrl);
      res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
      next();
});


// Bitcoin blockchain requirements:
const bip39 = require('bip39')
const bitcoin = require('bitcoinjs-lib')
const ecc = require('tiny-secp256k1')
const { BIP32Factory } = require('bip32')
const bip32 = BIP32Factory(ecc)
const sb = require('satoshi-bitcoin')
let network = bitcoin.networks.testnet



//#region ==================== BLOCKCHAIN FUNCTIONS ====================
/**
 * A Bitcoin Account. 
 */
class account {
      constructor(adr, pub, prv, wif) {
            this.adr = adr; // Address: Public bitcoin address
            this.pub = pub; // PublicKey
            this.prv = prv; // PrvateKey
            this.wif = wif; // WIF
      }
}


/**
 * Drives a full aacount from the given key. Always gives the same output for the same input.
 * @param {bitcoin.networks} network Bitcoin mainnet/testnet
 * @param {string} pathIndex Index of the child
 * @param {string} mainPrivateKey The Main Private Key which all childs are driven from
 * @returns account [object] {address, publicKey, privateKey, WIF}
 */
async function setupAccount(pathIndex, mainPrivateKey) {
      console.log('setup account with: ' + pathIndex + ' - ' + mainPrivateKey)
      var path = "m/49'/0/" + pathIndex;
      const root = bip32.fromSeed(
            Buffer.from(
                  mainPrivateKey,
                  'hex',
            ),
      );
      const child1 = root.derivePath(path);
      var privateWIF = child1.toWIF()
      let publicAddress = bitcoin.payments.p2pkh({
            pubkey: child1.publicKey,
            network: network,
      }).address
      var newAccount = new account(publicAddress, child1.publicKey.toString('hex'), child1.privateKey.toString('hex'), privateWIF)
      return Promise.resolve(newAccount)
}


async function fetchData(senderAddress, destinationAddress, txAmount, periority, gassAmount) {
      try {
            if (gassAmount != 0) {

                  gassFee = gassAmount
                  isGassFeeSet = true
            } else {
                  getFees(periority)
            }

            var url = process.env.blockCypheruri
            if (network == bitcoin.networks.testnet) {
                  url += 'test3/addrs/' + senderAddress + '/full?limit=50&unspentOnly=true&includeScript=true'

            } else {
                  url += 'main/addrs/' + senderAddress + '/full?limit=50&unspentOnly=true&includeScript=true'
            }
            console.log('call for data - url: ' + url)
            https.get(url, (resp) => {
                  let data = '';
                  resp.on('data', (chunk) => { data += chunk })
                  resp.on('end', () => {

                        console.log('http get adress info res:')
                        var res = JSON.parse(data).txs;
                        res.sort(function (a, b) {
                              var c = new Date(a.confirmed);
                              var d = new Date(b.confirmed);
                              return d - c;
                        });


                        var allHashs = new Array();
                        var spentHashs = new Array();
                        for (let i = 0; i < res.length; i++) {
                              var iHash = res[i].hash;
                              allHashs.push(iHash)
                              for (let j = 0; j < res.length; j++) {
                                    var ins = res[j].inputs;
                                    for (let k = 0; k < ins.length; k++) {
                                          if (ins[k].prev_hash == iHash) {
                                                console.log('i: ' + i + '   j: ' + j + '   k: ' + k)
                                                spentHashs.push(iHash)
                                          };
                                    }
                              }
                        }
                        utxoHashs = getSpendableHashs(allHashs, spentHashs);
                        isUtxoHashsReady = true
                        console.log('utxoHashs:')
                        console.log(utxoHashs)


                        createInputs(utxoHashs, senderAddress, txAmount).then((res) => {
                              console.log('###   createInputs    END res:')
                              console.log(res)
                              opInputs = res;
                              isInputReady = true;
                              createOutputs(txAmount, senderAddress, destinationAddress, periority, network).then((res) => {
                                    console.log('createOutputs Done')
                                    console.log(res)

                              })

                        })
                        return JSON.parse(data)
                  });
            }).on("error", (err) => {
                  console.log(err)
                  return res.status(501).json({
                        status: "error", data: err.message
                  });
            })
      } catch (error) {
            return {
                  status: "error", data: error.message
            }
      }
}

var transferError = false
var transferErrorMessage = ''
async function createTransaction(signer) {
      try {


            var psbt = new bitcoin.Psbt({ network: network })
            psbt.network = network
            if (psbt.network == bitcoin.networks.testnet) {
                  console.log('Testnet is set...')
            } else if (psbt.network == bitcoin.networks.bitcoin) {
                  console.log('Maninet is set...')
            } else {
                  console.log('Unable to detect the network... ***********')
            }

            console.log('addInput @ END OK 0')

            // Add Inputs for the new Transaction
            for (let i = 0; i < opInputs.length; i++) {
                  console.log('opInputs.length: ')
                  console.log(opInputs.length)
                  console.log(opInputs[i])
                  psbt.addInput(opInputs[i])
            }

            console.log('addInput @ END OK 2')

            //Add Outputs for the new Transaction
            for (let i = 0; i < opOutputs.length; i++) {
                  console.log(opOutputs[i])
                  psbt.addOutput(opOutputs[i])
            }

            console.log('opOutpu OK')
            psbt.signInput(0, signer);

            console.log('##6')
            psbt.finalizeAllInputs();

            console.log('##7')

            var res = psbt.extractTransaction().toHex()

            console.log('##8')
            console.log('res')
            console.log(res)
            //wwww
            rawTransaction = {
                  tx: res
            };
            console.log('TRX SENT')

            //return (pushtx)
      } catch (error) {
            transferErrorMessage = error.message
            transferError = true
      }

}
var rawTransaction = undefined

async function createInputs(spendables, senderAddress, txAmount) {
      //var bud = require('.')
      console.log('## createInputs Start')
      console.log('##0')
      var inps = new Array()
      var inputsTotalValue = 0
      return new Promise((resolve, reject) => {
            console.log('## createInputs Start Inside the promise')
            console.log('## spendables: ')
            console.log(spendables)
            for (let i = 0; i < spendables.length; i++) {
                  console.log('##fetchTransactionHex i: ' + i)
                  fetchTransactionHex(spendables[i], senderAddress, network).then((res) => {
                        console.log('##1 - 1 - UTXO result OK  ')
                        console.log(res)
                        if (res.status == 'success') {

                              for (let j = 0; j < res.outputs.length; j++) {
                                    console.log('res.outputs[j]')
                                    console.log(res.outputs[j].output)
                                    inputsTotalValue += res.outputs[j].output.value;
                                    console.log('inputsTotalValue: ' + inputsTotalValue)
                                    var newInp = {
                                          hash: spendables[i],
                                          index: res.outputs[j].index,
                                          nonWitnessUtxo: Buffer.from(res.hex, 'hex')
                                    }
                                    inps.push(newInp)
                              }
                              if (inputsTotalValue >= txAmount) {
                                    // End of this
                                    console.log('## createInputs End of this')
                                    accessableValue = inputsTotalValue;
                                    resolve(inps);
                              }
                        } else {
                              generalError('Couldn\'t fetch Transaction hex', res.error)
                              reject('Couldn\'t fetch Transaction hex', res.error)
                        }
                  });
            }
            console.log('##2 - end of fetching hexes')
      })
}

async function createOutputs(txAmount, senderAddress, destinationAddress, perority) {
      var leftedValue = accessableValue - txAmount;
      if (!isGassFeeSet) { await getFees(perority) }
      //var estimatedConsumption = gasFeeRate * defaultVSize * 0.001;
      console.log('createOutputs info: txAmount: ' + txAmount + ' - accessableValue: ' + accessableValue +
            ' - leftedValue: ' + leftedValue + ' - gassFee: ' + gassFee)
      opOutputs = new Array()
      opOutputs.push({ address: destinationAddress, value: txAmount })
      if (leftedValue > gassFee + 10) {
            changeAmount = leftedValue - gassFee
            opOutputs.push({ address: senderAddress, value: changeAmount })
      }
      isOutputReady = true
      setTimeout(() => {
            createTransaction(signer)

      }, 500);

      return Promise.resolve(opOutputs)
}

async function getFees(perority) {
      console.log('call for Fee Rate - perority: ' + perority)

      var url = process.env.blockCypheruri
      if (network == bitcoin.networks.testnet) {
            url += 'test3'

      } else {
            url += 'main'
      }
      console.log('call for Fee Rate - url: ' + url)
      return new Promise((resolve, reject) => {
            https.get(url, (resp) => {
                  console.log('Fee Rate call #0')
                  let data = '';
                  resp.on('data', (chunk) => { data += chunk })
                  resp.on('end', () => {
                        console.log('Fee Rate call #1 : done')
                        var res = JSON.parse(data)
                        //console.log(res)

                        var rate = 0
                        switch (perority) {
                              case 'high':
                                    rate = res.high_fee_per_kb
                              case 'med':
                                    rate = res.medium_fee_per_kb
                              case 'low':
                                    rate = res.low_fee_per_kb

                        }
                        console.log('Fee Rate call #2 : rate= ' + rate)
                        gassFee = rate
                        isGassFeeSet = true
                        resolve(rate)
                  });
            }).on("error", (err) => {
                  console.log('#1 Error')
                  console.log(err)
                  var res = {
                        status: 'error',
                        error: err,
                  }
                  reject(res)
            })
      })
      //HERE WORKING

}


async function fetchTransactionHex(txId, senderAddress) {
      var url = process.env.blockCypheruri

      if (network == bitcoin.networks.testnet) {
            url += 'test3/txs/' + txId + '?limit=50&includeHex=true'

      } else {
            url += 'main/txs/' + txId + '?limit=50&includeHex=true'

      }
      console.log('call for TX hash - url: ' + url)

      return new Promise((resolve, reject) => {
            https.get(url, (resp) => {
                  console.log('TX hash call #0')
                  let data = '';
                  resp.on('data', (chunk) => { data += chunk })
                  resp.on('end', () => {
                        console.log('http get tx hash result done')
                        var result = JSON.parse(data)
                        var hex = result.hex;
                        var outputs = new Array();
                        for (let i = 0; i < result.outputs.length; i++) {
                              var output = result.outputs[i];
                              //console.log(output)
                              for (let j = 0; j < output.addresses.length; j++) {
                                    if (output.addresses[j] == senderAddress) {
                                          outputs.push({ output: output, index: i })
                                    }
                              }
                        }
                        var res = {
                              status: 'success',
                              hex: hex,
                              outputs: outputs
                        }
                        console.log(res)
                        resolve(res)
                  });
            }).on("error", (err) => {
                  console.log('#1 Error')
                  console.log(err)
                  var res = {
                        status: 'error',
                        error: err,
                  }
                  reject(res)
            })
      })
}

function getSpendableHashs(all, spent) {
      var res = new Array();
      for (let i = 0; i < all.length; i++) {
            var isExist = false;
            var checkingHash = all[i];
            for (let j = 0; j < spent.length; j++) {
                  if (checkingHash == spent[j]) {
                        isExist = true;
                  }

            }
            if (!isExist) {
                  res.push(checkingHash)
            }


      }
      return res
}



// Unspent Transactions hashs which is fetched via API
var utxoHashs = ''
var isUtxoHashsReady = false

// Inputs which will be added as the TX inputs. Array of {hash, index, nonWitnessUtxo}
var opInputs = undefined
var isInputReady = false

// Outputs which will be added as the TX inputs. Array of {address, value}
var opOutputs = undefined
var isOutputReady = false

var accessableValue = 0

// Represents the raw transaction size in Bytes
var defaultVSize = 1000;

// The amount which will be transfered back to the addres
var changeAmount = 0;

var gassFee = 0
var isGassFeeSet = false
//#endregion ================ END BLOCKCHAIN FUNCTIONS =================


//#region ==================== SERVER FUNCTIONS ====================


// ========== Register
app.post("/register", express.json({ type: '*/*' }), async (req, res) => {
      try {
            console.log('--register--')
            await mongoose.connect(dburi)
            var Inp = req.body
            if (Inp.username.length < 6) {
                  return res.status(400).send('Username must be at least 6 chars long.');
            }
            if (Inp.password.length < 6) {
                  return res.status(400).send('Username must be at least 6 chars long.');
            }
            let exists = await User.exists({ username: Inp.username });

            if (exists) {
                  return res.status(400).send('Username already exists.');
            }
            console.log('Validation OK')

            // Latest Address Seed
            var LAS = undefined
            var vall = await Data.findOne({ key: 'latestAD2' })
            //.then(async (vv) => {
            LAS = Number(vall.value) + 1

            console.log('LAS:')
            console.log(LAS)

            let mpk = process.env.mpk
            var newAccount = await setupAccount(LAS.toString(), mpk)
            console.log('newAccount')
            console.log(newAccount)




            var newUser = {
                  username: Inp.username,
                  passwordhash: encrypt(Inp.password),
                  AuthToken: crypto.randomUUID(),
                  keepSigned: Date.now() + (60 * 60 * 1000),
                  address: newAccount.adr,
                  addressDA1: 0,
                  addressDA2: LAS,
                  extraInfo: ''
            }
            console.log('newUser before add ')
            console.log(newUser)

            User.create(newUser).then(async (result) => {
                  console.log('add success')
                  console.log(result)
                  await Data.findOneAndUpdate({ key: 'latestAD2' }, { value: LAS })

                  return res.status(200).json({
                        status: 'success', data: {
                              id: result._id,
                              AuthToken: newUser.AuthToken,
                              address: newUser.address,
                              username: newUser.username
                        }
                  });

            }).catch((error) => {
                  console.log('add error')
                  console.log(error)
                  return res.status(500).json({
                        status: 'error', data: error.message, errorText: 'Could not connect to database. Please try later'
                  });
            })
      } catch (error) {
            console.log('add error catch')
            console.log(error)

            return res.status(501).json({
                  status: 'error', data: error, errorText: 'Could not Create the account. Please try later'
            });
      }

})



// ========== Login
app.post("/login", express.json({ type: '*/*' }), async (req, res) => {
      try {

            console.log('--login--')
            console.info(req.body)
            var Inp = req.body
            if (Inp.username.length < 6) {
                  return res.status(400).send('Username must be at least 6 chars long.');
            }
            if (Inp.password.length < 6) {
                  return res.status(400).send('Username must be at least 6 chars long.');
            }
            console.log('Validation OK')

            await mongoose.connect(dburi)

            let exists = await User.exists({ username: Inp.username });

            if (!exists) {
                  return res.status(400).send('Username does not exists.');
            }
            var user = await User.findOne({ username: Inp.username });
            let epw = encrypt(Inp.password)
            if (epw != user.passwordhash) {
                  return res.status(400).send('Wrong Password.');
            }

            console.log('login is ok')

            user.AuthToken = crypto.randomUUID()
            var date = Date.now() + (60 * 60 * 1000);

            console.log('===============')
            console.log(date)
            console.log(Date.now())
            console.log('===============')
            if (Inp.remember) {
                  date += (48 * 60 * 60 * 1000);
            }

            user.keepSigned = date


            //cccc
            await User.findOneAndUpdate({ username: Inp.username }, user)
            console.log('login end. After Update - user:')

            console.log('The input user:')
            console.log(user)

            var fuser = await User.findOne({ username: Inp.username })
            console.log('The fetched user:')
            console.log(fuser)

            return res.status(200).json({
                  status: 'success',
                  data: {
                        AuthToken: user.AuthToken,
                        address: user.address,
                        username: user.username,
                        keepSigned: user.keepSigned
                  }

            });

      } catch (error) {
            console.log('add error catch')
            console.log(error)

            return res.status(501).json({
                  status: 'error', data: error
            });
      }

})


// ========== Transfer
const ECPairFactory = require('ecpair');
const ECPair = ECPairFactory.ECPairFactory(ecc);
app.post("/transfer", express.json({ type: '*/*' }), async (req, res) => {
      try {
            console.log('--transfer--')
            var Inp = req.body

            // Validations
            if (Inp.username.length < 6) {
                  return res.status(400).send('Username must be at least 6 chars long.');
            }
            if (Inp.token.length < 30) {
                  return res.status(400).send('Authentication failed.');
            }
            if (Inp.token.length < 30) {
                  return res.status(400).send('Authentication failed.');
            }
            console.log('validation OK')



            //Authentication
            var dbStatus = await dbConnect()
            if (!dbStatus) {
                  console.log('Database Connection Failed.')
                  return res.status(400).send('Database Connection Failed.');
            }
            console.log('Database Connection OK')

            let exists = await User.exists({ username: Inp.username });
            console.log('User exists: ' + exists)

            if (!exists) {
                  return res.status(400).send('Username does not exists.');
            }
            console.log('User existed')

            var user = await User.findOne({ username: Inp.username });
            console.log('User fetchde')

            if (Inp.token != user.AuthToken) {
                  return res.status(400).send('Authentication failed.');
            }

            if (Inp.keepSigned <= Date.now()) {
                  return res.status(400).send('Authentication failed. Session Expired.');
            }


            console.log('Authentication is ok')



            // Operation - fetch user account
            let mpk = process.env.mpk
            var userAccount = await setupAccount(user.addressDA2.toString(), mpk)
            console.log('userAccount')
            console.log(userAccount)



            // Operation - creating the transaction
            senderAddress = userAccount.adr
            ECPair.network = network
            signer = ECPair.fromWIF(userAccount.wif)
            await fetchData(senderAddress, Inp.destination, sb.toSatoshi(Inp.amount), Inp.periority, Number(Inp.gassAmount))



            // Operation - returning the transaction
            var counter = 0
            var resultInterval = setInterval(() => {
                  if (rawTransaction != undefined) {
                        clearInterval(resultInterval)
                        console.log('TX OK')
                        return res.status(200).json({
                              status: 'success', data: rawTransaction
                        });
                  }
                  else if (transferError) {
                        console.log('transferError')

                        return res.status(400).json({
                              status: 'error', data: {
                                    errorText: transferErrorMessage,
                              }
                        });
                  }
                  else {
                        counter++

                        if (counter > 10) {
                              return res.status(400).json({
                                    status: 'error', data: 'Could not operate. Try later'
                              });
                        }
                  }
            }, 1000);
      } catch (error) {
            return res.status(501).json({
                  status: 'error', data: {
                        errorText: 'Could not operate. Try later',
                        error: error
                  }
            });
      }
})



// ========== Check Availability
app.get("/health", async (req, res) => {
      console.log('health')
      return res.status(200).json({
            status: "success"
      });
})


// ========== Check Status
app.get("/status", async (req, res) => {
      console.log('status check started')

      var dbStatus = await dbConnect()
      if (dbStatus) {
            console.log('status check: OK - from : ')
            return res.status(200).json({
                  status: "success"
            });
      }
      console.log('status check: Error')

      return res.status(501).json({
            status: "error"
      });
})


// ========== Get Fees
app.get("/fees", async (req, res) => {
      console.log('Fee Rate call #1')
      var url = process.env.blockCypheruri

      if (network == bitcoin.networks.testnet) {
            url += 'test3'

      } else {
            url += 'main'
      }
      console.log('call for Fee Rate on gett fee - url: ' + url)
      https.get(url, (resp) => {
            console.log('Fee Rate call #1')
            let data = '';
            resp.on('data', (chunk) => { data += chunk })
            resp.on('end', () => {
                  console.log('Fee Rate call #1 : done')
                  var rates = JSON.parse(data)
                  //console.log(res)
                  return res.status(200).json({
                        status: "success", data: {
                              high: rates.high_fee_per_kb,
                              med: rates.medium_fee_per_kb,
                              low: rates.low_fee_per_kb
                        }
                  });
            });
      }).on("error", (err) => {
            console.log('#1 Error')
            console.log(err)

            return res.status(501).json({
                  status: "error",
                  error: err.message,
                  errorText: "Could not fetch fees."
            });
      })
})



// ========== Running the server
const server = app.listen(port, async () => { //ssss
      console.log(`Example app listening on port ${port}!`);
      // var m = encrypt('Hello world. from the server. I want to test and see what will happen if i give it longer string')
      // console.log(m)
      // var n = decrypt(m)
      // console.log(n)
      for (let i = 0; i < 10; i++) {

            var d = crypto.randomUUID()
            //var d = encrypt(Date.now().toString())
            console.log(d)
      }

});

server.keepAliveTimeout = 120 * 1000;
server.headersTimeout = 120 * 1000;

//#region CRyptography
//const ENC = 'bf3c199c2470cb977d907b1e0a17c17b';
const ENC = process.env.secret32;
//const IV = "wewewewewewewewe";
const IV = process.env.secret16;
const ALGO = "aes-256-cbc"

const encrypt = ((text) => {
      let cipher = crypto.createCipheriv(ALGO, ENC, IV);
      let encrypted = cipher.update(text, 'utf8', 'base64');
      encrypted += cipher.final('base64');
      return encrypted;
});

const decrypt = ((text) => {
      let decipher = crypto.createDecipheriv(ALGO, ENC, IV);
      let decrypted = decipher.update(text, 'base64', 'utf8');
      return (decrypted + decipher.final('utf8'));
});

// const algorithm = 'aes-256-ctr';
// const ENCRYPTION_KEY = 'adadadadadadadad'; // or generate sample key Buffer.from('FoCKvdLslUuB4y3EZlKate7XGottHski1LmyqJHvUhs=', 'base64');
// const IV_LENGTH = 16;

// function encrypt(text) {
//       let iv = crypto.randomBytes(IV_LENGTH);
//       let cipher = crypto.createCipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
//       let encrypted = cipher.update(text);
//       encrypted = Buffer.concat([encrypted, cipher.final()]);
//       return iv.toString('hex') + ':' + encrypted.toString('hex');
// }

// function decrypt(text) {
//       let textParts = text.split(':');
//       let iv = Buffer.from(textParts.shift(), 'hex');
//       let encryptedText = Buffer.from(textParts.join(':'), 'hex');
//       let decipher = crypto.createDecipheriv(algorithm, Buffer.from(ENCRYPTION_KEY, 'hex'), iv);
//       let decrypted = decipher.update(encryptedText);
//       decrypted = Buffer.concat([decrypted, decipher.final()]);
//       return decrypted.toString();
// }
//#endregion CRyptography

//

async function dbConnect() {
      return new Promise((resolve, reject) => {
            console.log('dbConnect start')
            if (mongoose.connection.readyState == 1) {
                  console.log('db is Connected')
                  resolve(true)
            } else {
                  var counter = 0;
                  mongoose.connect(dburi)
                  var interval = setInterval(() => {
                        if (mongoose.connection.readyState == 1) {
                              clearInterval(interval)
                              console.log('db has got Connected')
                              resolve(true)
                        }
                        counter++
                        if (counter > 30) {
                              console.log('db Connect Failed')
                              clearInterval(interval)
                              resolve(false)
                        }
                        console.log('DB Conneting attempt ' + counter
                        )
                  }, 1000)
            }
      })
}


// Temporary Database function sample
async function getVal() {
      //create
      //return await Promise.resolve(await Data.create({ key: 'latestAD2', value: 0 }))

      //get
      return await Promise.resolve(await Data.findOne({ key: 'latestAD2' }))

      //Update
      //return await Promise.resolve(await Data.findOneAndUpdate({ key: 'latestAD2' }, { value: -1 }))

      //Delete
      // return await Promise.resolve(await Data.deleteOne({ _id: '64bd0b620a22dbdf0b110e98' }))
}






// //Encrypting text
// function encrypt(text) {
//       let secret = process.env.secret
//       let key = crypto.createHash('sha256').update(String(secret)).digest('base64').substring(0, 32);
//       let iv = crypto.createHash('sha256').update(String(secret)).digest('base64').substring(0, 16);
//       let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
//       let encrypted = cipher.update(text);
//       encrypted = Buffer.concat([encrypted, cipher.final()]);
//       //return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
//       return encrypted.toString('hex');
// }

// // Decrypting text
// function decrypt(text) {
//       let iv = Buffer.from(text.iv, 'hex');
//       let encryptedText = Buffer.from(text.encryptedData, 'hex');
//       let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
//       let decrypted = decipher.update(encryptedText);
//       decrypted = Buffer.concat([decrypted, decipher.final()]);
//       return decrypted.toString();
// }


//#endregion ==================== END SERVER FUNCTIONS ====================
