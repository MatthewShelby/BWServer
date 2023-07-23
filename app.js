const express = require("express");
const app = express();
require("dotenv").config();
const port = process.env.PORT || 3001;
const mongoose = require("mongoose");
const Data = require('./class')
const User = require('./UserCS')
var dburi = process.env.dburi
//const dbcs = `mongodb+srv://broker:wGokfsvMGnFW5DY7@cluster0.kkxdm.mongodb.net/APT?retryWrites=true`
const dbcs = `mongodb+srv://broker:wGokfsvMGnFW5DY7@cluster0.kkxdm.mongodb.net/APT?retryWrites=true&w=majority?directConnection=true`
mongoose.connect(dburi)



// ========== Check Availability
app.post("/register", express.json({ type: '*/*' }), async (req, res) => {


      try {
            console.log('req.body:')
            console.info(req.body)
            var Inp = req.body
            if (Inp.username.length < 6) {
                  return res.status(400).send('Username must be at least 6 chars long.');
            }
            if (Inp.password.length < 6) {
                  return res.status(400).send('Username must be at least 6 chars long.');
            }
            let exists = await User.exists({ username: Inp.username });

            // var lad = await Data.find({ key: 'latestAD2' });
            // await Data.create({ key: 'latestAD2', value: '0' });
            // console.log(lad)

            if (exists) {
                  return res.status(400).send('Username already exists.');
            }
            console.log('Validation OK')
            var datetime = new Date();

            var lad = await Data.find({ key: 'latestAD2' });
            console.log('lad:')
            console.log(lad)


            User.create({
                  username: Inp.username,
                  passwordhash: encrypt(Inp.password),
                  keepToken: crypto.randomUUID(),
                  keepSigned: datetime.setHours(datetime.getHours() + 1),
                  address: 'bc1slrng9tb9gnspfvna0erfn',
                  extraInfo: ''

            }).then((result) => {
                  console.log('add success')
                  console.log(result)
                  return res.status(200).json({
                        status: 'success', id: result._id
                  });
            }).catch((error) => {
                  console.log('add error')
                  console.log(error)
                  return res.status(500).json({
                        status: 'error', data: error.message
                  });
            })


      } catch (error) {
            console.log('add error catch')
            console.log(error)

            return res.status(501).json({
                  status: 'error', data: error
            });
      }

})


const crypto = require('crypto');




// ========== Check Availability
app.get("/health", async (req, res) => {
      return res.status(200).json({
            status: "success"
      });
})





const server = app.listen(port, () => {
      console.log(`Example app listening on port ${port}!`);
      //Data.create({ key: 'latestAD2', value: '0' });
      Data.find({ key: 'latestAD2' }).then((res) => {
            console.log('lad:')
            console.log(res)
      });

      User.find({ username: 'aaaaaaaa' }).then((res) => {
            console.log('user:')
            console.log(res)
      });


}
);

server.keepAliveTimeout = 120 * 1000;
server.headersTimeout = 120 * 1000;







//Encrypting text
function encrypt(text) {
      let secret = process.env.secret
      let key = crypto.createHash('sha256').update(String(secret)).digest('base64').substring(0, 32);
      let iv = crypto.createHash('sha256').update(String(secret)).digest('base64').substring(0, 16);
      let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key), iv);
      let encrypted = cipher.update(text);
      encrypted = Buffer.concat([encrypted, cipher.final()]);
      //return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
      return encrypted.toString('hex');
}

// Decrypting text  
function decrypt(text) {
      let iv = Buffer.from(text.iv, 'hex');
      let encryptedText = Buffer.from(text.encryptedData, 'hex');
      let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key), iv);
      let decrypted = decipher.update(encryptedText);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      return decrypted.toString();
}