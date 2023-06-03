/**
 * Generates a cryptographic key pair asynchronously.
 * @param {AlgorithmIdentifier} alg - The algorithm to be used for key generation.
 * @param {Array} scope - The scope of the key pair.
 * @returns {Promise<CryptoKeyPair>} A promise that resolves to the generated key pair.
 */

function generateKey(alg, scope) {
  return new Promise(function (resolve) {
    var genkey = crypto.subtle.generateKey(alg, true, scope);
    genkey.then(function (pair) {
      resolve(pair);
    });
  });
}

/**
 * Converts an ArrayBuffer to a Base64-encoded string.
 * @param {ArrayBuffer} arrayBuffer - The ArrayBuffer to be converted.
 * @returns {string} The Base64-encoded string.
 */

function arrayBufferToBase64String(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var byteString = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    byteString += String.fromCharCode(byteArray[i]);
  }
  return btoa(byteString);
}

/**
 * Converts a Base64-encoded string to an ArrayBuffer.
 * @param {string} b64str - The Base64-encoded string.
 * @returns {ArrayBuffer} The converted ArrayBuffer.
 */

function base64StringToArrayBuffer(b64str) {
  var byteStr = atob(b64str);
  var bytes = new Uint8Array(byteStr.length);
  for (var i = 0; i < byteStr.length; i++) {
    bytes[i] = byteStr.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Converts a text string to an ArrayBuffer.
 * @param {string} str - The text string to be converted.
 * @returns {Uint8Array} The converted ArrayBuffer.
 */

function textToArrayBuffer(str) {
  var buf = unescape(encodeURIComponent(str)); // 2 bytes for each char
  var bufView = new Uint8Array(buf.length);
  for (var i = 0; i < buf.length; i++) {
    bufView[i] = buf.charCodeAt(i);
  }
  return bufView;
}

/**
 * Converts an ArrayBuffer to a text string.
 * @param {ArrayBuffer} arrayBuffer - The ArrayBuffer to be converted.
 * @returns {string} The converted text string.
 */

function arrayBufferToText(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var str = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    str += String.fromCharCode(byteArray[i]);
  }
  return str;
}

/**
 * Converts an ArrayBuffer to a Base64-encoded string.
 * @param {ArrayBuffer} arr - The ArrayBuffer to be converted.
 * @returns {string} The Base64-encoded string.
 */

function arrayBufferToBase64(arr) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(arr)));
}

/**
 * Converts binary data to a PEM format.
 * @param {ArrayBuffer} binaryData - The binary data to be converted.
 * @param {string} label - The label for the PEM format.
 * @returns {string} The converted PEM format.
 */

function convertBinaryToPem(binaryData, label) {
  var base64Cert = arrayBufferToBase64String(binaryData);
  var pemCert = "-----BEGIN " + label + "-----\r\n";
  var nextIndex = 0;
  var lineLength;
  while (nextIndex < base64Cert.length) {
    if (nextIndex + 64 <= base64Cert.length) {
      pemCert += base64Cert.substr(nextIndex, 64) + "\r\n";
    } else {
      pemCert += base64Cert.substr(nextIndex) + "\r\n";
    }
    nextIndex += 64;
  }
  pemCert += "-----END " + label + "-----\r\n";
  return pemCert;
}

/**
 * Converts a PEM format to binary data.
 * @param {string} pem - The PEM format string.
 * @returns {ArrayBuffer} The binary data.
 */

function convertPemToBinary(pem) {
  var lines = pem.split("\n");
  var encoded = "";
  for (var i = 0; i < lines.length; i++) {
    if (
      lines[i].trim().length > 0 &&
      lines[i].indexOf("-BEGIN RSA PRIVATE KEY-") < 0 &&
      lines[i].indexOf("-BEGIN RSA PUBLIC KEY-") < 0 &&
      lines[i].indexOf("-END RSA PRIVATE KEY-") < 0 &&
      lines[i].indexOf("-END RSA PUBLIC KEY-") < 0
    ) {
      encoded += lines[i].trim();
    }
  }
  return base64StringToArrayBuffer(encoded);
}

/**
 * Imports a public key from a PEM format.
 * @param {string} pemKey - The PEM format public key.
 * @returns {Promise<CryptoKey>} A promise that resolves to the imported public key.
 */

function importPublicKey(pemKey) {
  return window.crypto.subtle.importKey(
    "spki",
    convertPemToBinary(pemKey),
    { name: "RSA-OAEP", hash: { name: "SHA-256" } },
    true,
    ["encrypt"]
  );
}

/**
 * Imports a private key from a PEM format.
 * @param {string} pemKey - The PEM format private key.
 * @returns {Promise<CryptoKey>} A promise that resolves to the imported private key.
 */

function importPrivateKey(pemKey) {
  return window.crypto.subtle.importKey(
    "pkcs8",
    convertPemToBinary(pemKey),
    { name: "RSA-OAEP", hash: { name: "SHA-256" } },
    true,
    ["decrypt"]
  );
}

/**
 * Exports a public key as a PEM format.
 * @param {CryptoKeyPair} keys - The key pair containing the public key.
 * @returns {Promise<string>} A promise that resolves to the public key in PEM format.
 */

function exportPublicKey(keys) {
  return new Promise(function (resolve) {
    window.crypto.subtle
      .exportKey("spki", keys.publicKey)
      .then(function (spki) {
        resolve(convertBinaryToPem(spki, "RSA PUBLIC KEY"));
      });
  });
}

/**
 * Exports a private key as a PEM format.
 * @param {CryptoKeyPair} keys - The key pair containing the private key.
 * @returns {Promise<string>} A promise that resolves to the private key in PEM format.
 */

function exportPrivateKey(keys) {
  return new Promise(function (resolve) {
    var expK = window.crypto.subtle.exportKey("pkcs8", keys.privateKey);
    expK.then(function (pkcs8) {
      resolve(convertBinaryToPem(pkcs8, "RSA PRIVATE KEY"));
    });
  });
}

/**
 * Exports the public and private keys as PEM format.
 * @param {CryptoKeyPair} keys - The key pair containing the public and private keys.
 * @returns {Promise<Object>} A promise that resolves to an object containing the public and private keys in PEM format.
 */

function exportPemKeys(keys) {
  return new Promise(function (resolve) {
    exportPublicKey(keys).then(function (pubKey) {
      exportPrivateKey(keys).then(function (privKey) {
        resolve({ publicKey: pubKey, privateKey: privKey });
      });
    });
  });
}

/**
 * Signs data using a cryptographic key.
 * @param {CryptoKey} key - The key used for signing.
 * @param {string} data - The data to be signed.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to the signature as an ArrayBuffer.
 */

function signData(key, data) {
  return window.crypto.subtle.sign(signAlgorithm, key, textToArrayBuffer(data));
}

/**
 * Verifies a signature for the given data using a public key.
 * @param {CryptoKey} pub - The public key used for verification.
 * @param {ArrayBuffer} sig - The signature to be verified.
 * @param {string} data - The data to verify the signature against.
 * @returns {Promise<boolean>} A promise that resolves to true if the signature is valid, false otherwise.
 */

function testVerifySig(pub, sig, data) {
  return crypto.subtle.verify(signAlgorithm, pub, sig, data);
}

/**
 * Generates and stores a cryptographic key pair in localStorage.
 * @returns {Promise<Object>} A promise that resolves to an object containing the generated key pair, public key, private key, and the actual CryptoKey pair for future use.
 */

async function generateAndStoreKey() {
  const storedKeys = localStorage.getItem("keys");
  let keys = storedKeys ? JSON.parse(storedKeys) : null;

  if (!keys) {
    // Generate new keys
    const algorithm = {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: { name: "SHA-256" }, // Specify the hash algorithm identifier
    };
    const keyPair = await generateKey(algorithm, ["encrypt", "decrypt"]);

    // Export the keys as PEM format
    const publicKey = await exportPublicKey(keyPair.publicKey);
    const privateKey = await exportPrivateKey(keyPair.privateKey);

    // Store the keys in localStorage
    keys = {
      publicKey: convertBinaryToPem(publicKey, "RSA PUBLIC KEY"),
      privateKey: convertBinaryToPem(privateKey, "RSA PRIVATE KEY"),
      keyPair: keyPair, // Store the actual CryptoKey pair for future use
    };
    localStorage.setItem("keys", JSON.stringify(keys));
  }

  // Import the keys for encryption and decryption
  keys.publicKey = await importPublicKey(keys.publicKey);
  keys.privateKey = await importPrivateKey(keys.privateKey);

  return keys;
}

/**
 * Encrypts data using a public key.
 * @param {CryptoKey} publicKey - The public key used for encryption.
 * @param {string} data - The data to be encrypted.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to the encrypted data as an ArrayBuffer.
 */

function encryptData(publicKey, data) {
  return window.crypto.subtle.encrypt(
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-256" },
    },
    publicKey,
    textToArrayBuffer(data)
  );
}

/**
 * Decrypts data using a private key.
 * @param {CryptoKey} privateKey - The private key used for decryption.
 * @param {ArrayBuffer} data - The data to be decrypted.
 * @returns {Promise<ArrayBuffer>} A promise that resolves to the decrypted data as an ArrayBuffer.
 */

function decryptData(privateKey, data) {
  return window.crypto.subtle.decrypt(
    {
      name: "RSA-OAEP",
      hash: { name: "SHA-256" },
    },
    privateKey,
    data
  );
}

// Usage example
generateAndStoreKey().then(function (keys) {
  console.log("Key Pair:", keys.keyPair);
  console.log("Public Key:", keys.publicKey);
  console.log("Private Key:", keys.privateKey);

  // Example usage: Encrypt and decrypt a message
  const message = "Hello, World!";
  const encryptedMessage = encryptData(keys.publicKey, message);
  encryptedMessage.then(function (encryptedData) {
    console.log("Encrypted Data:", encryptedData);
    console.log("Encrypted Data:", arrayBufferToBase64String(encryptedData));

    const decryptedMessage = decryptData(keys.privateKey, encryptedData);
    decryptedMessage.then(function (decryptedData) {
      const decryptedText = arrayBufferToText(decryptedData);
      console.log("Decrypted Text:", decryptedText);
    });
    const decryptedMessageFromBase64 = decryptData(
      keys.privateKey,
      base64StringToArrayBuffer(arrayBufferToBase64String(encryptedData))
    );
    decryptedMessageFromBase64.then(function (decryptedData) {
      const decryptedText = arrayBufferToText(decryptedData);
      console.log("Decrypted Text:", decryptedText);
    });
  });
});
