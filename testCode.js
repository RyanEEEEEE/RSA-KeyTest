function generateKey(alg, scope) {
  return crypto.subtle.generateKey(alg, true, scope);
}

function arrayBufferToBase64String(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var byteString = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    byteString += String.fromCharCode(byteArray[i]);
  }
  return btoa(byteString);
}

function base64StringToArrayBuffer(b64str) {
  var byteStr = atob(b64str);
  var bytes = new Uint8Array(byteStr.length);
  for (var i = 0; i < byteStr.length; i++) {
    bytes[i] = byteStr.charCodeAt(i);
  }
  return bytes.buffer;
}

function textToArrayBuffer(str) {
  var buf = unescape(encodeURIComponent(str)); // 2 bytes for each char
  var bufView = new Uint8Array(buf.length);
  for (var i = 0; i < buf.length; i++) {
    bufView[i] = buf.charCodeAt(i);
  }
  return bufView;
}

function arrayBufferToText(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var str = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    str += String.fromCharCode(byteArray[i]);
  }
  return str;
}

function arrayBufferToBase64(arr) {
  return btoa(String.fromCharCode.apply(null, new Uint8Array(arr)));
}

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

function importPublicKey(pemKey) {
  return new Promise(function (resolve) {
    var importer = crypto.subtle.importKey(
      "spki",
      convertPemToBinary(pemKey),
      { name: "RSA-OAEP", hash: { name: "SHA-256" } },
      true,
      ["encrypt"]
    );
    importer.then(function (key) {
      resolve(key);
    });
  });
}

function importPrivateKey(pemKey) {
  return new Promise(function (resolve) {
    var importer = crypto.subtle.importKey(
      "pkcs8",
      convertPemToBinary(pemKey),
      { name: "RSA-OAEP", hash: { name: "SHA-256" } },
      true,
      ["decrypt"]
    );
    importer.then(function (key) {
      resolve(key);
    });
  });
}

function exportPublicKey(key) {
  return crypto.subtle.exportKey("spki", key);
}

function exportPrivateKey(key) {
  return crypto.subtle.exportKey("pkcs8", key);
}

function signData(key, data) {
  return crypto.subtle.sign(
    { name: "RSA-PSS", saltLength: 32 },
    key,
    textToArrayBuffer(data)
  );
}

function verifySignature(key, signature, data) {
  return crypto.subtle.verify(
    { name: "RSA-PSS", saltLength: 32 },
    key,
    signature,
    textToArrayBuffer(data)
  );
}

function encryptData(key, data) {
  return crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    key,
    textToArrayBuffer(data)
  );
}

function decryptData(key, data) {
  return crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, data);
}

// Generate Key Pair for Encryption/Decryption
var encryptionKeyPairAlgorithm = {
  name: "RSA-OAEP",
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: { name: "SHA-256" },
};
var encryptionKeyUsageScope = ["encrypt", "decrypt"];

// Generate Key Pair for Signing/Verifying
var signingKeyPairAlgorithm = {
  name: "RSA-PSS",
  modulusLength: 2048,
  publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
  hash: { name: "SHA-256" },
};
var signingKeyUsageScope = ["sign", "verify"];

generateKey(encryptionKeyPairAlgorithm, encryptionKeyUsageScope).then(function (
  encryptionKeyPair
) {
  var encryptionPublicKey = encryptionKeyPair.publicKey;
  var encryptionPrivateKey = encryptionKeyPair.privateKey;

  generateKey(signingKeyPairAlgorithm, signingKeyUsageScope).then(function (
    signingKeyPair
  ) {
    var signingPublicKey = signingKeyPair.publicKey;
    var signingPrivateKey = signingKeyPair.privateKey;

    // Export Public and Private Keys
    exportPublicKey(encryptionPublicKey).then(function (
      encryptionPublicKeyExported
    ) {
      var exportedEncryptionPublicKey = convertBinaryToPem(
        encryptionPublicKeyExported,
        "RSA PUBLIC KEY"
      );
      console.log(
        "Exported Encryption Public Key:",
        exportedEncryptionPublicKey
      );
    });

    exportPrivateKey(encryptionPrivateKey).then(function (
      encryptionPrivateKeyExported
    ) {
      var exportedEncryptionPrivateKey = convertBinaryToPem(
        encryptionPrivateKeyExported,
        "RSA PRIVATE KEY"
      );
      console.log(
        "Exported Encryption Private Key:",
        exportedEncryptionPrivateKey
      );
    });

    exportPublicKey(signingPublicKey).then(function (signingPublicKeyExported) {
      var exportedSigningPublicKey = convertBinaryToPem(
        signingPublicKeyExported,
        "RSA PUBLIC KEY"
      );
      console.log("Exported Signing Public Key:", exportedSigningPublicKey);
    });

    exportPrivateKey(signingPrivateKey).then(function (
      signingPrivateKeyExported
    ) {
      var exportedSigningPrivateKey = convertBinaryToPem(
        signingPrivateKeyExported,
        "RSA PRIVATE KEY"
      );
      console.log("Exported Signing Private Key:", exportedSigningPrivateKey);
    });

    // Example Usage: Encrypt and Decrypt
    var plaintext = "Hello, World!";
    encryptData(encryptionPublicKey, plaintext).then(function (ciphertext) {
      console.log("Ciphertext:", arrayBufferToBase64(ciphertext));
      decryptData(encryptionPrivateKey, ciphertext).then(function (
        decryptedText
      ) {
        console.log("Decrypted Text:", arrayBufferToText(decryptedText));
      });
    });

    // Example Usage: Sign and Verify
    var message = "This is a message to be signed.";
    signData(signingPrivateKey, message).then(function (signature) {
      console.log("Signature:", arrayBufferToBase64(signature));
      verifySignature(signingPublicKey, signature, message).then(function (
        isValid
      ) {
        console.log("Is Valid Signature:", isValid);
      });
    });
  });
});
