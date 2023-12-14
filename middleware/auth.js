const jwt = require("jsonwebtoken");
const config = process.env;
const crypto = require("crypto");
const bodyParser = require("body-parser");
const { Session } = require("inspector");
const SessionCollection = require("./../model/session");
const UserCollection = require("./../model/user");
const { request } = require("http");

async function createFinger(fingerprint) {
  const hashedFingerprint = crypto
    .createHash("sha256")
    .update(fingerprint)
    .digest("hex");
  return hashedFingerprint;
}

const authMiddleware = async (req, res, next) => {
  console.log("middleware hit");
  console.log("Token:", req.body.headers.Authorization);
  // console.log("Fingerprint:", req.body.headers.fingerprint);
  const token =
    req.headers["authorization"] ||
    req.body.headers.Authorization ||
    req.body.headers.Authorization ||
    req.body.headers["Authorization"];
  let decoded = null;
  if (!token) {
    console.log("Missing token");
    return res.status(200).send({ message: "Missing token", data: null });
  }

  try {
    decoded = jwt.verify(token, config.TOKEN_KEY);
    console.log(decoded);
    const currentTimestamp = Math.floor(Date.now() / 1000);
    // const currentTimestampInSeconds = Math.floor(Date.now() / 1000);
    console.log(currentTimestamp, decoded.expireTimestamp);
    if (decoded.expireTimestamp && decoded.expireTimestamp < currentTimestamp) {
      console.log("Expired token");
      return res.status(200).send({ message: "Expired", data: null });
    }
    req.token = token;
    req.user = decoded;
    let fingerHash = await createFinger(req.body.headers.fingerprint);
    if (fingerHash !== decoded.fingerPrintHash) {
      console.log("Token hijacked!! Logged out and cleaned session");
      return res.status(200).send({
        message: "Token hijacked!! Logged out and cleaned session.",
        data: null,
      });
    }
    try {
      let sessionId = decoded.createdSession;
      let session = await SessionCollection.findOne({ _id: sessionId });
      console.log("session", session);
      if (session) {
        let currentTimestamp = new Date();
        let expireTimestamp = new Date(session.expireTimestamp);

        if (currentTimestamp > expireTimestamp) {
          return res.status(200).send({
            message: "Session Expired!",
            data: null,
          });
        } else {
          console.log("Session is still valid");
          let user = await UserCollection.findOne({ email: session.email });
          if (user) {
            req.user = user;
            return next();
          } else {
            return res.status(200).send({
              message: "User not found, please log in again!",
              data: null,
            });
          }
        }
      } else {
        return res.status(200).send({
          message: "Session not found, please log in again!",
          data: null,
        });
      }
    } catch (err) {
      console.error(err);
      return res.status(200).send({ message: "Request expire!", data: null });
    }
  } catch (err) {
    console.error(err);
    return res.status(200).send({ message: "Invalid", data: null });
  }
  // return next();
};

module.exports = authMiddleware;
