function Base64encode(buffer){
  const str = String.fromCharCode.apply(null, new Uint8Array(buffer));
  return window.btoa(str);
}