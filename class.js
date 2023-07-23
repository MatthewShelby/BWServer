const mongoose = require("mongoose");

const dataSchema = new mongoose.Schema({
      key: String,
      value: String
})
module.exports = mongoose.model("Data", dataSchema)



// const userSchema = new mongoose.Schema({
//       username: { type: String, required: true, lowercase: true, minLength: 6, maxLength: 24 },
//       passwordhash: String,
//       keepToken: String,
//       keepSigned: Date,
//       address: String,
//       addressDA1: Number,
//       addressDA2: Number,
//       extraInfo: String,
// })

// // module.exports = mongoose.model("User", userSchema)


// const User = mongoose.model('user', userSchema)
// const Data = mongoose.model('data', dataSchema)

// module.exports = { User: User, Data: Data }