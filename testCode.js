function generateKey(alg, scope) {
    return new Promise(function (resolve) {
      var genkey = crypto.subtle.generateKey(alg, true, scope);
      genkey.then(function (pair) {
        resolve(pair);
      });
    });
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
        signAlgorithm,
        true,
        ["verify"]
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
        signAlgorithm,
        true,
        ["sign"]
      );
      importer.then(function (key) {
        resolve(key);
      });
    });
  }

  function exportPublicKey(keys) {
    return new Promise(function (resolve) {
      window.crypto.subtle
        .exportKey("spki", keys.publicKey)
        .then(function (spki) {
          resolve(convertBinaryToPem(spki, "RSA PUBLIC KEY"));
        });
    });
  }

  function exportPrivateKey(keys) {
    return new Promise(function (resolve) {
      var expK = window.crypto.subtle.exportKey("pkcs8", keys.privateKey);
      expK.then(function (pkcs8) {
        resolve(convertBinaryToPem(pkcs8, "RSA PRIVATE KEY"));
      });
    });
  }

  function exportPemKeys(keys) {
    return new Promise(function (resolve) {
      exportPublicKey(keys).then(function (pubKey) {
        exportPrivateKey(keys).then(function (privKey) {
          resolve({ publicKey: pubKey, privateKey: privKey });
        });
      });
    });
  }

  function signData(key, data) {
    return window.crypto.subtle.sign(
      signAlgorithm,
      key,
      textToArrayBuffer(data)
    );
  }

  function testVerifySig(pub, sig, data) {
    return crypto.subtle.verify(signAlgorithm, pub, sig, data);
  }

  function encryptData(vector, key, data) {
    return crypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
        iv: vector,
      },
      key,
      textToArrayBuffer(data)
    );
  }

  function decryptData(vector, key, data) {
    return crypto.subtle.decrypt(
      {
        name: "RSA-OAEP",
        iv: vector,
      },
      key,
      data
    );
  }

// Check if keys exist in localStorage
const publicKeyExists = localStorage.getItem('publicKey');
const privateKeyExists = localStorage.getItem('privateKey');

if (publicKeyExists && privateKeyExists) {
  // Keys already exist, retrieve them from localStorage
  const publicKeyPem = publicKeyExists;
  const privateKeyPem = privateKeyExists;

  // Call the necessary functions to import the keys
  importPublicKey(publicKeyPem)
    .then(publicKey => {
      console.log('Public Key (Imported):', publicKey);
      // Use the public key as needed
    })
    .catch(error => {
      console.error('Error importing public key:', error);
    });

  importPrivateKey(privateKeyPem)
    .then(privateKey => {
      console.log('Private Key (Imported):', privateKey);
      // Use the private key as needed
    })
    .catch(error => {
      console.error('Error importing private key:', error);
    });
} else {
  // Generate RSA key pair
  generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, ['encrypt', 'decrypt'])
    .then(pair => {
      // Export public and private keys to PEM format
      exportPemKeys(pair)
        .then(keys => {
          console.log('Public Key (PEM):', keys.publicKey);
          console.log('Private Key (PEM):', keys.privateKey);

          // Save keys in localStorage
          localStorage.setItem('publicKey', keys.publicKey);
          localStorage.setItem('privateKey', keys.privateKey);

          // Use the generated keys as needed
        })
        .catch(error => {
          console.error('Export PEM Keys Error:', error);
        });
    })
    .catch(error => {
      console.error('Key Generation Error:', error);
    });
}