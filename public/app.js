/////////////////////////////////////////////////////////
//             Firebase Cloud Functions                //
/////////////////////////////////////////////////////////

var functions = firebase.functions();
var registerPublicKey = firebase.functions().httpsCallable('registerPublicKey');
var requestAuthPhase1 = firebase.functions().httpsCallable('requestAuthPhase1');
var requestAuthPhase2 = firebase.functions().httpsCallable('requestAuthPhase2');

/////////////////////////////////////////////////////////
//             Firebase Cloud Functions                //
/////////////////////////////////////////////////////////

firebase.auth().onAuthStateChanged(function(user) {
  if (user) {
    console.log(user);
  } else {
    console.log('User is signed out.');
  }
});

/////////////////////////////////////////////////////////
//                Helper Functions                     //
/////////////////////////////////////////////////////////

function derivePublicKey(privateKey){
  return crypto.subtle.exportKey('jwk', privateKey)
  .then((exportedKey) => {
    return crypto.subtle.importKey(
      'jwk',
      {
        crv: "P-256",
        ext: true,
        key_ops: ["verify"],
        kty: "EC",
        x: exportedKey.x,
        y: exportedKey.y
      },
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      true,
      ["verify"]
    );
  });
}

function getRawPublicKey(publicKey){
  return window.crypto.subtle.exportKey('raw',publicKey);
}

function derivePublicAddress(rawPublicKey){
  var publicKeyHash = new Uint8Array(21);
  var pubAddr = new Uint8Array(25);

  return window.crypto.subtle.digest('SHA-256', rawPublicKey)
  .then((hash1)=>{
    return ripemd160(hash1);
  })
  .then((hash2)=>{
    publicKeyHash[0] = 0;
    publicKeyHash.set(hash2,1);
    return window.crypto.subtle.digest('SHA-256', publicKeyHash);
  })
  .then((hash3)=>{
    return window.crypto.subtle.digest('SHA-256', hash3);
  })
  .then((hash4)=>{
    var checksum = new Uint8Array(hash4.slice(0,4));
    pubAddr.set(publicKeyHash);
    pubAddr.set(checksum,publicKeyHash.length);
    return Base58.encode(pubAddr);
  });
}

function generateKeyFromPassword(password, salt){
  const enc = new TextEncoder();

  return window.crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    {name: "PBKDF2"},
    false,
    ["deriveBits", "deriveKey"]
  ).then((keyMaterial) => {
    return window.crypto.subtle.deriveKey(
      {
        "name": "PBKDF2",
        salt: salt,
        "iterations": 100000,
        "hash": "SHA-256"
      },
      keyMaterial,
      { "name": "AES-GCM", "length": 256},
      true,
      [ "wrapKey", "unwrapKey" ]
    );
  });
}

/////////////////////////////////////////////////////////
//                   GUI Functions                     //
/////////////////////////////////////////////////////////

var publicKey;
var privateKey;
var publicAddress;

function log(logtext){
  logarea.value = logarea.value + logtext + '\r\n\r\n';
  console.log(logtext);
}

function generate(){
  return window.crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    true,
    ["sign", "verify"]
  )
  .then((keyPair) => {
    privateKey = keyPair.privateKey;
    publicKey = keyPair.publicKey;

    crypto.subtle.exportKey('jwk', privateKey).then((exportedKey) => {
      log('Private key generated: ' + exportedKey.d);
    });

    crypto.subtle.exportKey('jwk', publicKey).then((exportedKey) => {
      log('Public key generated: \r\n    x: ' + exportedKey.x + '\r\n    y: ' + exportedKey.y);
    });

    return getRawPublicKey(publicKey)
    .then((rawPublicKey) => {
      return derivePublicAddress(rawPublicKey);
    })
    .then((pubAddr) => {
      publicAddress = pubAddr;
      log('Public address generated: ' + pubAddr);
      return;
    });
  });
}

function sendpublic() {
  return crypto.subtle.exportKey('spki', publicKey)
  .then ((exportedKey)=>{
    log('Sending public key and public address to the server...');
    return registerPublicKey({publicAddress: publicAddress, publicKey: Base64encode(exportedKey)});
  })
  .then(function(result) {
    log('Public key and public address sent to the server');
    console.log(result);
    return;
  });
}

function storekeys() {
  const id = keyid.value;
  const password = keypw.value;

  if (id == "" || password == "") {
    log("Missing KeyID or password");
    return;
  }
  log('Saving wrapped private key...');

  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  return generateKeyFromPassword(password, salt)
  .then((wrappingKey)=>{
    return window.crypto.subtle.wrapKey(
      "jwk",
      privateKey,
      wrappingKey,
      {
        name: "AES-GCM",
        iv: iv
      }
    );
  })
  .then((wrappedKey) => {
    storeValue = {salt: ArrayToHex(salt), iv: ArrayToHex(iv), wrappedKey: ArrayToHex(new Uint8Array(wrappedKey))};
    log('Saved wrapped private key:' + JSON.stringify(storeValue));
    return window.localStorage.setItem(id,JSON.stringify(storeValue));
  });
}

function loadkeys() {
  const id = keyid.value;
  const password = keypw.value;

  if (id == "" || password == "") {
    log("Missing KeyID or password");
    return;
  }
  log('Loading wrapped private key...');

  const storeValue = JSON.parse(window.localStorage.getItem(id));
  const iv = ArrayToArrayBuffer(HexToArray(storeValue.iv));
  const salt = ArrayToArrayBuffer(HexToArray(storeValue.salt));
  const wrappedKey = ArrayToArrayBuffer(HexToArray(storeValue.wrappedKey));

  log('Loaded wrapped private key:' + JSON.stringify(storeValue));

  return generateKeyFromPassword(password, salt)
  .then((unwrappingKey)=>{
    return window.crypto.subtle.unwrapKey(
      "jwk",
      wrappedKey,
      unwrappingKey,
      {
        name: "AES-GCM",
        iv: iv
      },
      {
        name: "ECDSA",
        namedCurve: "P-256"
      },
      true,
      ["sign"]
    );
  })
  .then((unwrappedKey)=>{
    privateKey = unwrappedKey;

    crypto.subtle.exportKey('jwk', privateKey).then((exportedKey) => {
      log('Private key loaded: ' + exportedKey.d);
    });

    return derivePublicKey(privateKey)
    .then((derivedKey) => {
      publicKey = derivedKey;

      crypto.subtle.exportKey('jwk', publicKey).then((exportedKey) => {
        log('Public key loaded: \r\n    x: ' + exportedKey.x + '\r\n    y: ' + exportedKey.y);
      });

      return getRawPublicKey(publicKey)
      .then((rawPublicKey) => {
        return derivePublicAddress(rawPublicKey);
      })
      .then((pubAddr) => {
        publicAddress = pubAddr;
        log('Public address loaded: ' + pubAddr);
        return;
      });
    });
  })
  .catch((err) =>{
    log ('error while loading/decrypting key: ' + err);
  });
}

function authenticate(){
  var randomHex;
  log('Requesting random number from the server associated with our public address...');
  return requestAuthPhase1({publicAddress: publicAddress})
  .then((result)=>{
    randomHex = result.data.random;
    log('Random number received: ' + randomHex);
    log('Signing random number...');
    return window.crypto.subtle.sign({name: "ECDSA", hash: {name: "SHA-256"}}, privateKey, HexToArray(randomHex));
  })
  .then((signature)=>{
    signatureArray = new Uint8Array(signature);
    signatureArrayDER = DERencode(signatureArray.slice(0,32),signatureArray.slice(32,64));
    log('Signature: ' + ArrayToHex(signatureArrayDER));
    log('Sending signature to server');
    return requestAuthPhase2({publicAddress: publicAddress, random: randomHex, signature: ArrayToHex(signatureArrayDER)});
  })
  .then((result) => {
    log('Authentication successful. Received token: ' + result.data.token);
    return firebase.auth().signInWithCustomToken(result.data.token);
  })
  .catch((err)=>{
    log('Authentication failed. Error: ' + err);
    console.log(err);
    return;
  });
}

const register = () => generate().then( () => sendpublic() ).then( () => storekeys());

const login = () => loadkeys().then( () => authenticate() );

var logarea = document.getElementById("log-area");
var keyid = document.getElementById("key-id");
var keypw = document.getElementById("key-pw");

//document.getElementById('generate-button').addEventListener('click', generate);
//document.getElementById('sendpublic-button').addEventListener('click', sendpublic);
//document.getElementById('store-button').addEventListener('click', storekeys);
//document.getElementById('load-button').addEventListener('click', loadkeys);
//document.getElementById('auth-button').addEventListener('click', authenticate);

document.getElementById('register-button').addEventListener('click', register);
document.getElementById('login-button').addEventListener('click', login);