'use strict';

const { Transform } = require('stream');
const crypto = require('crypto');

const cipherInfoMap = {
  'aes-128-cfb': { keyLen: 16, ivLen: 16 },
  'aes-192-cfb': { keyLen: 24, ivLen: 16 },
  'aes-256-cfb': { keyLen: 32, ivLen: 16 },
  'aes-128-ctr': { keyLen: 16, ivLen: 16 },
  'aes-192-ctr': { keyLen: 24, ivLen: 16 },
  'aes-256-ctr': { keyLen: 32, ivLen: 16 },
};

function md5(b) {
  return crypto.createHash('md5').update(b).digest();
}

// copy from shadowsocks-go evpBytesToKey
function _evpBytesToKey(password, keyLen) {
  password = Buffer.from(password);
  const md5Len = 16;
  const cnt = parseInt((keyLen - 1) / md5Len) + 1;
  const m = Buffer.allocUnsafe(cnt * md5Len);
  md5(password).copy(m);

  // Repeatedly call md5 until bytes generated is enough.
  // Each call to md5 uses data: prev md5 sum + password.
  const d = Buffer.allocUnsafe(md5Len + password.length);
  let start = 0;
  for (let i = 0; i < cnt; i++) {
    start += md5Len;
    m.copy(d, 0, start - md5Len, start);
    password.copy(d, md5Len);
    md5(d).copy(m, start);
  }

  return m.slice(0, keyLen);
}

const keyCache = new Map();
function evpBytesToKey(password, keyLen) {
  const cacheKey = password + keyLen;
  let value = keyCache.get(cacheKey);
  if (value) return value;
  value = _evpBytesToKey(password, keyLen);
  keyCache.set(cacheKey, value);
  return value;
}

class Encryptor extends Transform {
  constructor(method, password) {
    super();

    const { keyLen, ivLen } = cipherInfoMap[method];
    const key = evpBytesToKey(password, keyLen);
    this.iv = crypto.randomBytes(ivLen);
    this.isPutIv = false;

    this.cipher = crypto.createCipheriv(method, key, this.iv);
  }

  update(chunk) {
    if (this.isPutIv) return this.cipher.update(chunk);

    this.isPutIv = true;
    return Buffer.concat([this.iv, this.cipher.update(chunk)]);
  }

  _transform(chunk, encoding, callback) {
    callback(null, this.update(chunk));
  }
}

class Decryptor extends Transform {
  constructor(method, password) {
    super();

    const { keyLen, ivLen } = cipherInfoMap[method];
    this.method = method;
    this.key = evpBytesToKey(password, keyLen);
    this.ivLen = ivLen;
    this.iv = null;
    this.isGetIv = false;
    this.cipher = null;
  }

  update(chunk) {
    if (this.isGetIv) return this.cipher.update(chunk);

    if (chunk.length < this.ivLen) throw new Error('invalid iv data');

    this.iv = chunk.slice(0, this.ivLen);
    this.isGetIv = true;
    this.cipher = crypto.createDecipheriv(this.method, this.key, this.iv);
    if (chunk.length > this.ivLen) return this.update(chunk.slice(this.ivLen));
  }

  _transform(chunk, encoding, callback) {
    callback(null, this.update(chunk));
  }
}

exports.cipherInfoMap = cipherInfoMap;
exports.Encryptor = Encryptor;
exports.Decryptor = Decryptor;
