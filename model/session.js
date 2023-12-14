const mongoose = require("mongoose");

const sessionSchema = new mongoose.Schema({
  email: { type: String },
  createTimestamp: { type: Date, default: Date.now },
  expireTimestamp: {
    type: Date,
    default: () => new Date(+new Date() + 50 * 60 * 1000),
  },
  ipAddress: String,
  userAgent: String,
  flag: { type: String, default: true },
});

module.exports = mongoose.model("session", sessionSchema);
