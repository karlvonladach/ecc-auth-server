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
//                Encode Functions                     //
/////////////////////////////////////////////////////////

function Base64encode(buffer){
  const str = String.fromCharCode.apply(null, new Uint8Array(buffer));
  return window.btoa(str);
}

function DERencode(x, y){
  var tmp;
  while (x.length > 0 && x[0] == 0){
    x = x.slice(1);
  }
  if (x[0] > 127){
    tmp = new Uint8Array(x.length + 1);
    tmp[0] = 0;
    tmp.set(x, 1);
    x = tmp;
  }
  while (y.length > 0 && y[0] == 0){
    y = y.slice(1);
  }
  if (y[0] > 127){
    tmp = new Uint8Array(y.length + 1);
    tmp[0] = 0;
    tmp.set(y, 1);
    y = tmp;
  }
  
  var encoded = new Uint8Array(2 + 2 + x.length + 2 + y.length);
  encoded[0] = 0x30; //array type
  encoded[1] = 2 + x.length + 2 + y.length;
  encoded[2] = 0x02; //integer type
  encoded[3] = x.length;
  encoded.set(x, 4);
  encoded[4+x.length] =  0x02; //integer type
  encoded[4+x.length+1] = y.length;
  encoded.set(y, 4+x.length+2);

  return encoded;
}

function ArrayToHex(array){
  if (!array) {
    return '';
  }
  var hexStr = '';
  for (var i = 0; i < array.length; i++) {
    var hex = (array[i] & 0xff).toString(16);
    hex = (hex.length === 1) ? '0' + hex : hex;
    hexStr += hex;
  }
  return hexStr.toUpperCase();
}

function HexToArray(string){
  if (!string) {
    return new Uint8Array();
  }
  var a = [];
  for (var i = 0, len = string.length; i < len; i+=2) {
    a.push(parseInt(string.substr(i,2),16));
  }
  return new Uint8Array(a);
}

function ArrayToArrayBuffer(bytes) {
  const bytesAsArrayBuffer = new ArrayBuffer(bytes.length);
  const bytesUint8 = new Uint8Array(bytesAsArrayBuffer);
  bytesUint8.set(bytes);
  return bytesAsArrayBuffer;
}

/////////////////////////////////////////////////////////
//                Helper Functions                     //
/////////////////////////////////////////////////////////

function generatePublicAddress(publicKey){
  var publicKeyHash = new Uint8Array(21);
  var pubAddr = new Uint8Array(25);

  return window.crypto.subtle.exportKey('raw',publicKey)
  .then((exportedKey)=>{
    return window.crypto.subtle.digest('SHA-256', exportedKey);
  })
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

function getKeyFromPassword(password, salt){
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
  window.crypto.subtle.generateKey(
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

    generatePublicAddress(publicKey).then((pubAddr) => {
      publicAddress = pubAddr;
      log('Public address generated: ' + pubAddr);
      return ;
    });
  });
}

function register() {
  crypto.subtle.exportKey('spki', publicKey)
  .then ((exportedKey)=>{
    log('Sending public key and public address to the server...');
    return registerPublicKey({publicAddress: publicAddress, publicKey: Base64encode(exportedKey)});
  })
  .then(function(result) {
    log('Public key and public address sent to the server');
    console.log(result);
  });
}

function store() {
  const id = keyid.value;
  const password = keypw.value;

  if (id == "" || password == "") {
    log("Missing KeyID or password");
    return;
  }
  log('Saving wrapped private key...');

  const salt = window.crypto.getRandomValues(new Uint8Array(16));
  const iv = window.crypto.getRandomValues(new Uint8Array(12));

  getKeyFromPassword(password, salt)
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
    window.localStorage.setItem(id,JSON.stringify(storeValue));
  });
}

function load() {
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

  getKeyFromPassword(password, salt)
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
      log('Public key loaded: \r\n    x: ' + exportedKey.x + '\r\n    y: ' + exportedKey.y);
    });
  })
  .catch((err) =>{
    log ('error while loading key: ' + err);
  });
}

function authenticate(){
  var randomHex;
  log('Requesting random number from the server associated with our public address...');
  requestAuthPhase1({publicAddress: publicAddress})
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
  });
}

var logarea = document.getElementById("log-area");
var keyid = document.getElementById("key-id");
var keypw = document.getElementById("key-pw");

document.getElementById('generate-button').addEventListener('click', generate);
document.getElementById('register-button').addEventListener('click', register);
document.getElementById('store-button').addEventListener('click', store);
document.getElementById('load-button').addEventListener('click', load);
document.getElementById('auth-button').addEventListener('click', authenticate);