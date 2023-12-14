require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const User = require("./model/user");
const Session = require("./model/session");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const authMiddleware = require("./middleware/auth");
const config = process.env;
const userAgent = require("user-agent");
const fingerprint = require("fingerprintjs2");
const uuid = require("uuid");
const cors = require("cors");
const crypto = require("crypto");
const bodyParser = require("body-parser");

const app = express();
app.use(cors());

app.use(express.json());
app.use(bodyParser.json());

app.get("/", (req, res) => {
  return res.status(200).json({ message: "Server is running..." });
});

async function createSession(email, ip, agent) {
  try {
    let ifExist = await Session.findOne({ email: email });
    if (ifExist) {
      return ifExist._id;
    } else {
      const session = await Session.create({
        email: email.toLowerCase(),
        ipAddress: ip,
        userAgent: agent,
      });
      return session._id.toString();
    }
  } catch (error) {
    console.error("Session creation failed:", error);
    return null;
  }
}

async function verifyAndRefreshToken(token) {
  try {
    const decoded = jwt.verify(token, config.TOKEN_KEY);
    console.log(decoded);
    console.log("email", decoded.email);
    const currentTimestamp = Math.floor(Date.now() / 1000);

    if (decoded.expireTimestamp && decoded.expireTimestamp < currentTimestamp) {
      return false;
    }

    if (shouldRefreshToken(decoded)) {
      console.log("Refreshing token");
      const newToken = generateNewToken(decoded.email, decoded.createdSession);
      let email = decoded.email;
      const existingUser = await User.findOne({ email });

      return { message: "Token refreshed", existingUser, newToken };
    } else {
      let email = decoded.email;
      const existingUser = await User.findOne({ email });
      return { message: "Token still valid", existingUser, token };
    }
  } catch (err) {
    console.error(err);
    throw new Error("Invalid token");
  }
}

function shouldRefreshToken(decoded) {
  console.log("Decoded token:", decoded);

  if (typeof decoded.exp !== "number" || isNaN(decoded.exp)) {
    console.error("Invalid exp in the token.");
    return false;
  }

  const timeDifference = decoded.exp - Math.floor(Date.now() / 1000);
  const timeDifferenceMinutes = timeDifference / 60;
  console.log("Time difference in minutes:", timeDifferenceMinutes);

  return timeDifferenceMinutes < 10;
}

function generateNewToken(email, createdSession) {
  return jwt.sign({ email, createdSession }, process.env.TOKEN_KEY, {
    expiresIn: "10.5m",
  });
}

async function createFinger(fingerprint) {
  const hashedFingerprint = crypto
    .createHash("sha256")
    .update(fingerprint)
    .digest("hex");
  return hashedFingerprint;
}

app.post("/reg", async (req, res) => {
  try {
    const { first_name, last_name, email, password } = req.body;

    if (!(email && password && first_name && last_name)) {
      return res.status(400).json({ error: "All input is required" });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res
        .status(409)
        .json({ error: "User already exists. Please login." });
    }

    const encryptedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      first_name,
      last_name,
      email: email.toLowerCase(),
      password: encryptedPassword,
    });

    const userAgent = req.get("user-agent");
    const createdSession = await createSession(email, req.ip, userAgent);

    if (!createdSession) {
      return res.status(500).json({ error: "Failed to create a session" });
    }

    const expirationTimeInSeconds = Math.floor(Date.now() / 1000) + 630;
    let fingerPrintHash = await createFinger(req.body.fingerprint);
    // console.log("fingerPrintHash", fingerPrintHash);

    const token = jwt.sign(
      {
        fingerPrintHash,
        createdSession,
        expireTimestamp: expirationTimeInSeconds,
      },
      process.env.TOKEN_KEY,
      { expiresIn: "2h" }
    );
    console.log(token, "token");
    user.token = token;
    return res.status(201).json(user);
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!(email && password)) {
      return res.status(400).json({ error: "All input is required" });
    }

    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
      const userAgent = req.get("user-agent");
      const createdSession = await createSession(email, req.ip, userAgent);

      if (!createdSession) {
        return res.status(500).json({ error: "Failed to create a session" });
      }

      const expirationTimeInSeconds = Math.floor(Date.now() / 1000) + 630; // 10.5 minutes in seconds
      let fingerPrintHash = await createFinger(req.body.fingerprint);
      const token = jwt.sign(
        {
          fingerPrintHash,
          createdSession,
          expireTimestamp: expirationTimeInSeconds,
        },
        process.env.TOKEN_KEY,
        {
          expiresIn: "2h",
        }
      );

      user.token = token;
      console.log(token, "token");
      return res.status(200).json(user);
    }

    return res.status(400).json({ error: "Invalid Credentials" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/welcome", authMiddleware, async (req, res) => {
  return res.status(200).send({ message: "Welcome", data: req.user });
  // try {
  //   const result = await verifyAndRefreshToken(req.headers.Authorization);
  //   if (result === false) {
  //     return res.status(401).send("Session has expired-fun");
  //   } else {
  //     return res.status(200).send({ message: "Welcome", data: result });
  //   }
  // } catch (err) {
  //   console.error(err);
  //   return res.status(500).json({ error: "Internal Server Error" });
  // }
});

// app.get("/info", async (req, res) => {
//   const ua = userAgent.parse(req.headers["user-agent"]);
//   if (!req.useragent) {
//     return res
//       .status(500)
//       .send({ message: "User agent information not available" });
//   }
//   const deviceInfo = {
//     browser: req.useragent.browser,
//     version: req.useragent.version,
//     os: req.useragent.os,
//     platform: req.useragent.platform,
//     source: req.headers["user-agent"],
//   };
//   console.log(deviceInfo);

//   return res.status(200).send({ message: "Welcome", data: deviceInfo });
// });

// app.use(express.static("public")); // Serve static files

// app.use((req, res, next) => {
//   req.userId = uuid.v4();
//   next();
// });

// const deviceInfoMap = {};

// app.get("/info", (req, res) => {
//   const fingerprintOptions = {
//     excludes: { userAgent: false },
//   };

//   fingerprint.get(fingerprintOptions, (components) => {
//     const fingerprintValue = components
//       .map((component) => component.value)
//       .join("");

//     const browserId = req.headers["user-agent"];
//     console.log(req);

//     const deviceId = uuid.v4();

//     if (deviceInfoMap[browserId]) {
//       responseData = {
//         fingerprint: fingerprintValue,
//         deviceId: deviceInfoMap[browserId].deviceId,
//         userId: req.userId,
//         // browserId: browserId,
//       };
//     } else {
//       // Store the new device ID for the browser
//       deviceInfoMap[browserId] = { deviceId };
//       responseData = {
//         fingerprint: fingerprintValue,
//         deviceId,
//         userId: req.userId,
//         // browserId: browserId,
//       };
//     }
//     console.log(responseData);

//     res.status(200).send({ message: "Welcome", data: responseData });
//   });
// });

// const secretKey = "yourSecretKey";

// app.post("/login1", (req, res) => {
//   const user = { id: 1, username: "example" };

//   const token = jwt.sign(
//     { user, fingerprint: req.body.fingerprint },
//     secretKey,
//     {
//       expiresIn: "1h",
//     }
//   );

//   res.json({ token });
// });

// app.post("/info", (req, res) => {
//   console.log(res.headers);
//   res.json({ success: true, message: "Fingerprint received successfully" });
// });

// function authenticateToken(req, res, next) {
//   const token = req.header("Authorization");
//   if (!token) return res.sendStatus(401);

//   jwt.verify(token, secretKey, (err, decoded) => {
//     if (err) return res.sendStatus(403);

//     // Check if the fingerprint in the token matches the current fingerprint
//     if (decoded.fingerprint !== req.fingerprint.hash) {
//       return res.sendStatus(403);
//     }

//     req.user = decoded.user;
//     next();
//   });
// }

/////Here

const mongoose = require("mongoose");

const signatureSchema = new mongoose.Schema({
  userId: String,
  signatureData: String,
});

const Signature = mongoose.model("Signature", signatureSchema);

// Save signature
// app.post("/saveSignature", async (req, res) => {
//   try {
//     const { userId, signatureData } = req.body;

//     const newSignature = new Signature({
//       userId,
//       signatureData,
//     });

//     const savedSignature = await newSignature.save();

//     res.json(savedSignature);
//   } catch (error) {
//     console.error(error);
//     res.status(500).send("Internal Server Error");
//   }
// });

// ... (other imports and configurations)

app.post("/saveSignature", async (req, res) => {
  try {
    const { userId, signatureData } = req.body;

    // Check if a signature with the same userId already exists
    const existingSignature = await Signature.findOne({ userId: userId });

    if (existingSignature) {
      return res
        .status(400)
        .json({ error: "Signature with this userId already exists" });
    }

    const newSignature = new Signature({
      userId,
      signatureData,
    });

    const savedSignature = await newSignature.save();

    res.json(savedSignature);
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

// ... (other routes)

// Fetch signature by userId
app.get("/getSignature/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;

    const signature = await Signature.findOne({ userId });

    if (!signature) {
      res.status(404).send("Signature not found");
      return;
    }

    res.json(signature);
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal Server Error");
  }
});

module.exports = app;
