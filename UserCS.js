const mongoose = require("mongoose");




const userSchema = new mongoose.Schema({
      username: { type: String, required: true, lowercase: true, minLength: 6, maxLength: 24 },
      passwordhash: String,
      AuthToken: String,
      keepSigned: Number,
      address: String,
      addressDA1: Number,
      addressDA2: Number,
      extraInfo: String,
})

module.exports = mongoose.model("User", userSchema)
