const functions = require('firebase-functions');
const admin = require('firebase-admin');
const crypto = require('crypto');
const Base58 = require("base-58");

admin.initializeApp();

const db = admin.firestore();

//Verifies if the publicAddress is derived from the publicKey
function verifyPublicAddress(publicAddress, publicKeyBase64){
  const SPKI_HEADER_LEN = 26;
  const KEY_LEN = 65;
  var publicKeySXY = Buffer.from(publicKeyBase64, 'base64').slice(SPKI_HEADER_LEN, SPKI_HEADER_LEN + KEY_LEN);

  console.log("public key: ", publicKeySXY);
  console.log("after sha256: ",crypto.createHash('sha256').update(publicKeySXY).digest());
  
  publicKeyHash = Buffer.concat([ Buffer.from([0x00]), 
                                  crypto.createHash('ripemd160')
                                        .update(crypto.createHash('sha256')
                                                      .update(publicKeySXY)
                                                      .digest())
                                        .digest()]);

  console.log("after ripemd160: ", publicKeyHash);

  publicKeyChecksum = crypto.createHash('sha256')
                            .update(crypto.createHash('sha256')
                                          .update(publicKeyHash)
                                          .digest())
                            .digest()
                            .slice(0,4);

  console.log("after crc: ", publicKeyChecksum);
  
  pubAddr = Buffer.concat([publicKeyHash, 
                           publicKeyChecksum]);

  console.log(Base58.encode(pubAddr));
  console.log(publicAddress);

  return (Base58.encode(pubAddr) === publicAddress);
}

//Verifies if the signature is valid
function verifySignature(dataHex, signatureHex, publicKeyBase64){
  return crypto.createVerify('SHA256')
               .update(dataHex,'hex')
               .end()
               .verify({key: '-----BEGIN PUBLIC KEY-----\n' + publicKeyBase64 + '\n-----END PUBLIC KEY-----', format: 'pem', type: 'spki'}, signatureHex, 'hex');
}

//receives public key and public address, and saves it into the database, using the public address as key/uid
exports.registerPublicKey = functions.https.onCall((data, context) => {
  let userRef = db.collection('users').doc(data.publicAddress);
  return userRef.get()
  .then((doc)=>{
    if (doc.exists){
      throw new Error('Public address already exists in database');
    }
    else {
      return verifyPublicAddress(data.publicAddress, data.publicKey);
    }
  })
  .then((valid)=>{
    if (!valid) {
      throw new Error('Public key not valid');
    }
    else {
      return userRef.set({publicKey: data.publicKey});
    }
  })
  .then(()=>{
    return {status: 'OK'};
  })
  .catch(err => {
    console.log(err);
    return {status: err};
  });
});

//receives public address, and generates a random number to be signed. Saves the random number in db, and sends it back
exports.requestAuthPhase1 = functions.https.onCall((data, context) => {
  var random;
  var userRef = db.collection('users').doc(data.publicAddress);
  return userRef.get()
  .then((doc)=>{
    if (!doc.exists) {
      throw new Error('Public address not found in database');
    } 
    else {
      random = crypto.randomBytes(64);
      return userRef.set({random: random.toString('hex')}, {merge: true});
    }
  })
  .then((ref)=>{
    console.log("auth1 ok");
    return {status: 'OK', random: random.toString('hex')};
  })
  .catch((err)=>{
    console.log("auth1 error");
    console.log(err);
    return {status: error}; 
  });
});

//receives a public address and the signed random number. Verifies the signature with the public key stored in the db.
//if verified, sends back a custom token to sign in with
exports.requestAuthPhase2 = functions.https.onCall((data, context) => {
  let userRef = db.collection('users').doc(data.publicAddress);
  return userRef.get()
  .then((doc)=>{
    if (!doc.exists) {
      throw new Error('Public address not found in database');
    } 
    else if (doc.data().random !== data.random){
      throw new Error('Random data outdated');
    } 
    else {
      return verifySignature(data.random, data.signature, doc.data().publicKey);
    }
  })
  .then((valid)=>{
    if (!valid){
      console.log('signature not valid');
      throw new Error('signature not valid');
    }
    else {
      console.log('signature valid');
      //TODO: remove random number from database
      return admin.auth().createCustomToken(data.publicAddress);
    }
  })
  .then((customToken)=>{
    return {status: 'OK', token: customToken};
  })
  .catch((err) => {
    console.log("auth2 error");
    console.log(err);
    return {status: err};
  });
});

//add the message into the messages collection of the recipient
//sends a notification to the recipient
//returns delivery status
exports.sendMessage = functions.https.onCall((data, context) => {
});

//read messages from the inbox of the authenticated user (and then deletes them)
exports.readMessages = functions.https.onCall((data, context) => {
});