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