var publicKey;
var privateKey;
var publicAddress;

// Initialize Cloud Functions through Firebase
var functions = firebase.functions();
var registerPublicKey = firebase.functions().httpsCallable('registerPublicKey');
var requestAuthPhase1 = firebase.functions().httpsCallable('requestAuthPhase1');
var requestAuthPhase2 = firebase.functions().httpsCallable('requestAuthPhase2');

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

function HexFromArray(buffer){
  if (!buffer) {
    return '';
  }
  var hexStr = '';
  for (var i = 0; i < buffer.length; i++) {
    var hex = (buffer[i] & 0xff).toString(16);
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

function generateKeyPair(){
  window.crypto.subtle.generateKey(
    {
      name: "ECDSA",
      namedCurve: "P-256"
    },
    true,
    ["sign", "verify"]
  ).then((keyPair) => {
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;
    generatePublicAddress(keyPair.publicKey).then((pubAddr)=>{
      publicAddress = pubAddr;
      pa.value = pubAddr;
    });
    return crypto.subtle.exportKey('jwk', keyPair.privateKey);
  }).then((exportedKey) => {
    console.log(exportedKey);
    d.value = exportedKey.d;
    x.value = exportedKey.x;
    y.value = exportedKey.y;
  });
}

function generatePublicAddress(publicKey){
  var publicKeyHash = new Uint8Array(21);
  var pubAddr = new Uint8Array(25);

  return window.crypto.subtle.exportKey('raw',publicKey)
  .then((exportedKey)=>{
    //console.log("exported key:", exportedKey);
    return window.crypto.subtle.digest('SHA-256', exportedKey);
  })
  .then((hash1)=>{
    //console.log("after sha256: ", hash1);
    return ripemd160(hash1);
  })
  .then((hash2)=>{
    //console.log("after ripemd160: ", hash2);
    publicKeyHash[0] = 0;
    publicKeyHash.set(hash2,1);
    return window.crypto.subtle.digest('SHA-256', publicKeyHash);
  })
  .then((hash3)=>{
    //console.log("after crc1 sha256: ", hash3);
    return window.crypto.subtle.digest('SHA-256', hash3);
  })
  .then((hash4)=>{
    //console.log("after crc2 sha256: ", hash4);
    var checksum = new Uint8Array(hash4.slice(0,4));
    pubAddr.set(publicKeyHash);
    pubAddr.set(checksum,publicKeyHash.length);
    return Base58.encode(pubAddr);
  });
}

function register() {
  crypto.subtle.exportKey('spki', publicKey)
  .then ((exportedKey)=>{
    console.log(exportedKey);
    const exportedAsString = ab2str(exportedKey);
    const exportedAsBase64 = window.btoa(exportedAsString);
    return registerPublicKey({publicAddress: publicAddress, publicKey: exportedAsBase64});
  })
  .then(function(result) {
    console.log(result);
  });
}

function authorize(){
  var randomHex;
  requestAuthPhase1({publicAddress: publicAddress})
  .then((result)=>{
    console.log(result);
    randomHex = result.data.random;
    console.log(HexToArray(randomHex).buffer);
    console.log(window.crypto.subtle.digest('SHA-256',HexToArray(randomHex).buffer));
    return window.crypto.subtle.sign({name: "ECDSA", hash: {name: "SHA-256"}}, privateKey, HexToArray(randomHex));
  })
  .then((signature)=>{
    console.log(signature);
    signatureArray = new Uint8Array(signature);
    requestAuthPhase2({publicAddress: publicAddress, random: randomHex, signature: HexFromArray(signatureArray)});
    // return window.crypto.subtle.verify({
    //   name: "ECDSA",
    //   hash: {name: "SHA-256"},
    // },
    // publicKey,
    // signature,
    // HexToArray(randomHex));
  });
  //.then(valid=>{ console.log(valid? "valid" : "not valid")});
}

var d = document.getElementById("privateKey");
var x = document.getElementById("publicKeyX");
var y = document.getElementById("publicKeyY");
var pa = document.getElementById("publicAddress");

document.getElementById('generate-button').addEventListener('click', generateKeyPair);
document.getElementById('register-button').addEventListener('click', register);
document.getElementById('auth-button').addEventListener('click', authorize);