"use strict";

const path = require("path");

function joinPaths(...parts) {
  return path.join(...parts);
}

module.exports = { joinPaths };
