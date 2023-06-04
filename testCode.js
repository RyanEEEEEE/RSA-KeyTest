function textToArrayBuffer(text) {
  var encoder = new TextEncoder();
  return encoder.encode(text);
}

function arrayBufferToText(buffer) {
  var decoder = new TextDecoder();
  return decoder.decode(buffer);
}

function arrayBufferToBase64(buffer) {
  var binary = "";
  var bytes = new Uint8Array(buffer);
  var len = bytes.byteLength;
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  var binary = window.atob(base64);
  var len = binary.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
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

function generateKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: "RSA-PSS",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-256" },
    },
    true,
    ["sign", "verify"]
  );
}

function generateKeyPairForEncryption() {
  return crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-256" },
    },
    true,
    ["encrypt", "decrypt"]
  );
}

function useKeys() {
  var message = prompt("What would you like to say?");
  console.log("Original Message:", message);

  // Check if keys are saved in localStorage
  var signingPublicKeyPem = localStorage.getItem("signingPublicKey");
  var signingPrivateKeyPem = localStorage.getItem("signingPrivateKey");
  var encryptionPublicKeyPem = localStorage.getItem("encryptionPublicKey");
  var encryptionPrivateKeyPem = localStorage.getItem("encryptionPrivateKey");

  if (
    signingPublicKeyPem &&
    signingPrivateKeyPem &&
    encryptionPublicKeyPem &&
    encryptionPrivateKeyPem
  ) {
    console.info("Using saved Crypto Keys...");

    // Keys are already saved, use them directly
    var signingPublicKeyPromise = crypto.subtle.importKey(
      "spki",
      base64ToArrayBuffer(signingPublicKeyPem),
      { name: "RSA-PSS", hash: { name: "SHA-256" } },
      true,
      ["verify"]
    );
    var signingPrivateKeyPromise = crypto.subtle.importKey(
      "pkcs8",
      base64ToArrayBuffer(signingPrivateKeyPem),
      { name: "RSA-PSS", hash: { name: "SHA-256" } },
      true,
      ["sign"]
    );
    var encryptionPublicKeyPromise = crypto.subtle.importKey(
      "spki",
      base64ToArrayBuffer(encryptionPublicKeyPem),
      { name: "RSA-OAEP", hash: { name: "SHA-256" } },
      true,
      ["encrypt"]
    );
    var encryptionPrivateKeyPromise = crypto.subtle.importKey(
      "pkcs8",
      base64ToArrayBuffer(encryptionPrivateKeyPem),
      { name: "RSA-OAEP", hash: { name: "SHA-256" } },
      true,
      ["decrypt"]
    );

    Promise.all([
      signingPublicKeyPromise,
      signingPrivateKeyPromise,
      encryptionPublicKeyPromise,
      encryptionPrivateKeyPromise,
    ]).then(function ([
      signingPublicKey,
      signingPrivateKey,
      encryptionPublicKey,
      encryptionPrivateKey,
    ]) {
      console.log("Signing Public Key:", signingPublicKey);
      console.log("Signing Private Key:", signingPrivateKey);
      console.log("Encryption Public Key:", encryptionPublicKey);
      console.log("Encryption Private Key:", encryptionPrivateKey);

      encryptData(encryptionPublicKey, message)
        .then(function (encrypted) {
          console.log("Encrypted Message:", arrayBufferToBase64(encrypted));

          return decryptData(encryptionPrivateKey, encrypted);
        })
        .then(function (decrypted) {
          console.log("Decrypted Message:", arrayBufferToText(decrypted));

          return signData(signingPrivateKey, message);
        })
        .then(function (signature) {
          console.log("Signature:", arrayBufferToBase64(signature));

          return verifySignature(signingPublicKey, signature, message);
        })
        .then(function (verified) {
          console.log("Signature Verified:", verified);
        });
    });
  } else {
    console.info("Generating new Crypto Keys...");
    // Generate new key pairs
    Promise.all([generateKeyPair(), generateKeyPairForEncryption()]).then(
      function ([signingKeyPair, encryptionKeyPair]) {
        var signingPublicKey = signingKeyPair.publicKey;
        var signingPrivateKey = signingKeyPair.privateKey;
        var encryptionPublicKey = encryptionKeyPair.publicKey;
        var encryptionPrivateKey = encryptionKeyPair.privateKey;

        console.log("Signing Public Key:", signingPublicKey);
        console.log("Signing Private Key:", signingPrivateKey);
        console.log("Encryption Public Key:", encryptionPublicKey);
        console.log("Encryption Private Key:", encryptionPrivateKey);

        // Export keys as PEM format
        Promise.all([
          crypto.subtle.exportKey("spki", signingPublicKey),
          crypto.subtle.exportKey("pkcs8", signingPrivateKey),
          crypto.subtle.exportKey("spki", encryptionPublicKey),
          crypto.subtle.exportKey("pkcs8", encryptionPrivateKey),
        ]).then(function ([
          signingPublicKeyExport,
          signingPrivateKeyExport,
          encryptionPublicKeyExport,
          encryptionPrivateKeyExport,
        ]) {
          // Convert exported keys to PEM format
          var signingPublicKeyPem = arrayBufferToBase64(signingPublicKeyExport);
          var signingPrivateKeyPem = arrayBufferToBase64(
            signingPrivateKeyExport
          );
          var encryptionPublicKeyPem = arrayBufferToBase64(
            encryptionPublicKeyExport
          );
          var encryptionPrivateKeyPem = arrayBufferToBase64(
            encryptionPrivateKeyExport
          );

          // Save keys in localStorage
          localStorage.setItem("signingPublicKey", signingPublicKeyPem);
          localStorage.setItem("signingPrivateKey", signingPrivateKeyPem);
          localStorage.setItem("encryptionPublicKey", encryptionPublicKeyPem);
          localStorage.setItem("encryptionPrivateKey", encryptionPrivateKeyPem);

          encryptData(encryptionPublicKey, message)
            .then(function (encrypted) {
              console.log("Encrypted Message:", arrayBufferToBase64(encrypted));

              return decryptData(encryptionPrivateKey, encrypted);
            })
            .then(function (decrypted) {
              console.log("Decrypted Message:", arrayBufferToText(decrypted));

              return signData(signingPrivateKey, message);
            })
            .then(function (signature) {
              console.log("Signature:", arrayBufferToBase64(signature));

              return verifySignature(signingPublicKey, signature, message);
            })
            .then(function (verified) {
              console.log("Signature Verified:", verified);
            });
        });
      }
    );
  }
}

useKeys();
