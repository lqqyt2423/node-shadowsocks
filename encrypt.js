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

// TODO
function evpBytesToKey(password, keyLen) {
  return Buffer.alloc(keyLen);
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
