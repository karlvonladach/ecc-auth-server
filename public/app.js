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

/////////////////////////////////////////////////////////
//                   GUI Functions                     //
/////////////////////////////////////////////////////////

var publicKey;
var privateKey;
var publicAddress;

function generate(){
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
    return generatePublicAddress(publicKey); 
  })
  .then((pubAddr)=>{
    publicAddress = pubAddr;
    pa.value = pubAddr;
    return crypto.subtle.exportKey('jwk', privateKey);
  }).then((exportedKey) => {
    d.value = exportedKey.d;
    x.value = exportedKey.x;
    y.value = exportedKey.y;
  });
}

function register() {
  crypto.subtle.exportKey('spki', publicKey)
  .then ((exportedKey)=>{
    return registerPublicKey({publicAddress: publicAddress, publicKey: Base64encode(exportedKey)});
  })
  .then(function(result) {
    console.log(result);
  });
}

function authorize(){
  var randomHex;
  requestAuthPhase1({publicAddress: publicAddress})
  .then((result)=>{
    randomHex = result.data.random;
    return window.crypto.subtle.sign({name: "ECDSA", hash: {name: "SHA-256"}}, privateKey, HexToArray(randomHex));
  })
  .then((signature)=>{
    signatureArray = new Uint8Array(signature);
    signatureArrayDER = DERencode(signatureArray.slice(0,32),signatureArray.slice(32,64));
    return requestAuthPhase2({publicAddress: publicAddress, random: randomHex, signature: ArrayToHex(signatureArrayDER)});
  })
  .then((result) => {
    return firebase.auth().signInWithCustomToken(result.data.token);
  })
  .catch((err)=>{
    console.log(err);
  });
}

var d = document.getElementById("privateKey");
var x = document.getElementById("publicKeyX");
var y = document.getElementById("publicKeyY");
var pa = document.getElementById("publicAddress");

document.getElementById('generate-button').addEventListener('click', generate);
document.getElementById('register-button').addEventListener('click', register);
document.getElementById('auth-button').addEventListener('click', authorize);