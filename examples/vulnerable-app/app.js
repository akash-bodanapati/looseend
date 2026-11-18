const express = require("express");
const crypto = require("crypto");
const https = require("https");
const leftPad = require("left-pad-pro"); // expect: SLOP002

const app = express();

function runExpression(input) {
  return eval(input); // expect: SEC003
}

function hashToken(token) {
  return crypto.createHash("md5").update(token).digest("hex"); // expect: SEC003
}

const agent = new https.Agent({ rejectUnauthorized: false }); // expect: SEC003

function loadSettings(raw) {
  try { return JSON.parse(raw); } catch (err) {} // expect: GAP003
}

// TODO: add rate limiting // expect: GAP001

// const legacyHandler = (req, res) => {  // expect: SLOP004
//   return res.send("legacy");
// };

app.get("/", (req, res) => {
  console.log("request received", req.url); // expect: SLOP005
  res.send(runExpression(req.query.q));
});

app.listen(3000);
