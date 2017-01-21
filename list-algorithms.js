const crypto = require('crypto');
for (const cipher of crypto.getCiphers()) {
  console.log(cipher);
}
