const crypto = require('crypto');

const tokenMap = {};
let algorithm, password, sessionTimeout, timeoutId;

function authorize(req, res) {
  // Check for existence of token.
  const encryptedToken = req.get('Authorization');
  if (!encryptedToken) {
    res.statusMessage = 'Token Required';
    res.status(499).send();
    return false;
  }

  const token = decrypt(encryptedToken);
  const [reqUsername] = token.split('|');

  // Check for matching cached token.
  const cachedToken = tokenMap[reqUsername];
  if (!cachedToken || cachedToken !== token) {
    return false;
  }

  // Check for request from a different client IP address.
  const [username, clientIP, timeout] = token.split('|');
  if (req.ip !== clientIP) {
    res.statusMessage = 'Invalid Token';
    res.status(499).send();
    return false;
  }

  // Check for expired token.
  const timeoutMs = Number(timeout);
  if (timeoutMs < Date.now()) {
    res.statusMessage = 'Session Timeout';
    res.status(440).send();
    delete tokenMap[username];
    return false;
  }

  return true;
}

/**
 * Configures auth token encryption and the session timeout.
 * @param alg the encryption algorithm name
 * @param pswd the encryption password
 * @param sto the session timeout duration in minutes
 */
function configure(alg, pswd, sto) {
  algorithm = alg;
  password = pswd;
  sessionTimeout = sto;
}

function decrypt(text) {
  validateEncryption();
  const decipher = crypto.createDecipher(algorithm, password);
  return decipher.update(text, 'hex', 'utf8') + decipher.final('utf8');
}

function deleteExpiredTokens() {
  Object.keys(tokenMap).forEach(username => {
    const encryptedToken = tokenMap[username];
    const token = decrypt(encryptedToken);
    const [, , timeout] = token.split('|');
    const timeoutMs = Number(timeout);
    if (timeoutMs < Date.now()) delete tokenMap[username];
  });
}

function deleteToken(req) {
  if (timeoutId) clearTimeout(timeoutId);

  const encryptedToken = req.get('Authorization');
  const token = decrypt(encryptedToken);
  const [username] = token.split('|');
  delete tokenMap[username];
}

function encrypt(text) {
  validateEncryption();
  const cipher = crypto.createCipher(algorithm, password);
  return cipher.update(text, 'utf8', 'hex') + cipher.final('hex');
}

function generateToken(username, req, res) {
  // If another token was previously generated,
  // cancel the timeout for its session.
  if (timeoutId) clearTimeout(timeoutId);

  // Generate a token based username, client ip address, and expiration time.
  const expires = new Date();
  expires.setMinutes(expires.getMinutes() + sessionTimeout);

  const token = `${username}|${req.ip}|${expires.getTime()}`;
  const encryptedToken = encrypt(token);

  tokenMap[username] = token;

  res.setHeader('Authorization', encryptedToken);

  timeoutId = setTimeout(
    () => {
      if (global.socket) {
        global.socket.emit('session-timeout');
        // Can't delete the token if the logout service
        // requires authorization.
      } else {
        delete tokenMap[username];
      }
    },
    sessionTimeout * 60 * 1000);
}

function validateEncryption() {
  if (!algorithm || !password) {
    throw new Error('auth.js requires calling ' +
      'configureEncryption before other functions');
  }
}

module.exports = {
  authorize, configure, deleteExpiredTokens,
  deleteToken, generateToken
};
