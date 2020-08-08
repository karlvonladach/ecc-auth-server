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