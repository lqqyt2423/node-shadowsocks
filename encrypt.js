'use strict';

const { Transform } = require('stream');
const crypto = require('crypto');
const hkdf = require('futoin-hkdf');

// the maximum size of payload in bytes
const MAX_PAYLOAD = 0x3fff;

// nonce size: 12, tag size: 16
const cipherInfoMap = {
  'chacha20-poly1305': { keyLen: 32, saltLen: 32 },
  'aes-256-gcm': { keyLen: 32, saltLen: 32 },
  'aes-192-gcm': { keyLen: 24, saltLen: 24 },
  'aes-128-gcm': { keyLen: 16, saltLen: 16 },
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

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
function increase(nonce) {
  for (let i = 0; i < 12; i++) {
    nonce[i] += 1;
    if (nonce[i] !== 0) return;
  }
}

class Encryptor extends Transform {
  constructor(method, password) {
    super();

    this.method = method;
    const { keyLen, saltLen } = cipherInfoMap[method];
    const mainkey = evpBytesToKey(password, keyLen);
    this.salt = crypto.randomBytes(saltLen);
    this.key = hkdf(mainkey, keyLen, { salt: this.salt, info: 'ss-subkey', hash: 'sha1' });
    this.nonce = Buffer.alloc(12);
    this.isPutSalt = false;
  }

  update(chunk) {
    if (this.isPutSalt) {
      const len = chunk.length;
      const times = Math.ceil(len / MAX_PAYLOAD);
      const bufs = [];

      for (let i = 1; i <= times; i++) {
        const payloadLen = i === times ? (len - MAX_PAYLOAD * (i - 1)) : MAX_PAYLOAD;

        // [encrypted payload length][length tag][encrypted payload][payload tag]
        // 34 = 16 + 16 + 2
        const buf = Buffer.allocUnsafe(payloadLen + 34);

        const cipher1 = crypto.createCipheriv(this.method, this.key, this.nonce, { authTagLength: 16 });
        const lenBuf = Buffer.allocUnsafe(2);
        lenBuf.writeUInt16BE(payloadLen);
        cipher1.update(lenBuf).copy(buf, 0);
        cipher1.final();
        cipher1.getAuthTag().copy(buf, 2);
        increase(this.nonce);

        const cipher2 = crypto.createCipheriv(this.method, this.key, this.nonce, { authTagLength: 16 });
        cipher2.update(chunk).copy(buf, 18);
        cipher2.final();
        cipher2.getAuthTag().copy(buf, payloadLen + 18);
        increase(this.nonce);

        bufs.push(buf);
      }

      return times === 1 ? bufs[0] : Buffer.concat(bufs, len);
    }

    this.isPutSalt = true;
    return Buffer.concat([this.salt, this.update(chunk)]);
  }

  _transform(chunk, encoding, callback) {
    callback(null, this.update(chunk));
  }
}

class Decryptor extends Transform {
  constructor(method, password, options = {}) {
    super();

    this.method = method;
    const { keyLen, saltLen } = cipherInfoMap[method];
    this.keyLen = keyLen;
    this.saltLen = saltLen;
    this.mainkey = evpBytesToKey(password, keyLen);
    this.isGetSalt = false;
    this.nonce = Buffer.alloc(12);

    this.salt = null;
    this.key = null;

    this._buf = null;
    this._chunkLen = 0;
    this._cipher2 = null;
    this._readedChunkLen = 0;
    this._waitAuthTag = false;

    this.isGotFirstPayload = true;
    this.firstPayload = null;
    // will emit "firstPayload" event but not transform firstPayload
    if (options.emitFirstPayload === true) {
      this.isGotFirstPayload = false;
      this.firstPayload = Buffer.allocUnsafe(0);
    }
  }

  update(chunk) {
    if (this.isGetSalt) {
      if (this._buf) {
        chunk = Buffer.concat([this._buf, chunk]);
        this._buf = null;
      }

      if (!this._waitAuthTag && this._chunkLen === 0) {
        // [encrypted payload length][length tag] = 2 + 16
        if (chunk.length < 18) {
          this._buf = chunk;
          return;
        } else {
          const cipher1 = crypto.createDecipheriv(this.method, this.key, this.nonce, { authTagLength: 16 });
          cipher1.setAuthTag(chunk.slice(2, 18));
          const lenBuf = cipher1.update(chunk.slice(0, 2));
          cipher1.final();
          this._chunkLen = lenBuf.readUInt16BE();
          if (this._chunkLen > MAX_PAYLOAD) throw new Error('invalid payload len');
          increase(this.nonce);

          if (chunk.length === 18) return;
          chunk = chunk.slice(18);
        }
      }

      if (!this._cipher2) {
        this._cipher2 = crypto.createDecipheriv(this.method, this.key, this.nonce, { authTagLength: 16 });
      }

      let buf;
      if (!this._waitAuthTag) {
        const needReadChunkLen = this._chunkLen - this._readedChunkLen;
        if (chunk.length < needReadChunkLen) {
          buf = this._cipher2.update(chunk);
          this._readedChunkLen += chunk.length;

          if (!this.isGotFirstPayload) {
            this.firstPayload = Buffer.concat([this.firstPayload, buf]);
            return;
          }

          return buf;
        }

        buf = this._cipher2.update(chunk.slice(0, needReadChunkLen));
        if (!this.isGotFirstPayload) this.firstPayload = Buffer.concat([this.firstPayload, buf]);
        this._waitAuthTag = true;
        chunk = chunk.slice(needReadChunkLen);
      }

      if (chunk.length < 16) {
        this._buf = chunk;
        if (!this.isGotFirstPayload) return;
        return buf;
      }

      this._cipher2.setAuthTag(chunk.slice(0, 16));
      this._cipher2.final();
      increase(this.nonce);

      if (!this.isGotFirstPayload) {
        this.emit('firstPayload', this.firstPayload);
        this.isGotFirstPayload = true;
        this.firstPayload = null;
        buf = null;
      }

      this._chunkLen = 0;
      this._readedChunkLen = 0;
      this._cipher2 = null;
      this._waitAuthTag = false;

      if (chunk.length === 16) return buf;

      chunk = chunk.slice(16);
      return Buffer.concat([buf || Buffer.allocUnsafe(0), this.update(chunk) || Buffer.allocUnsafe(0)]);
    }

    if (chunk.length < this.saltLen) throw new Error('invalid salt');
    this.salt = chunk.slice(0, this.saltLen);
    this.key = hkdf(this.mainkey, this.keyLen, { salt: this.salt, info: 'ss-subkey', hash: 'sha1' });
    this.isGetSalt = true;
    if (chunk.length > this.saltLen) return this.update(chunk.slice(this.saltLen));
  }

  _transform(chunk, encoding, callback) {
    const buf = this.update(chunk);
    callback(null, buf || Buffer.allocUnsafe(0));
  }

  _flush() {
    if (this._buf || this._chunkLen || this._cipher2 || this._waitAuthTag) {
      throw new Error('invalid data');
    }
  }
}

exports.cipherInfoMap = cipherInfoMap;
exports.Encryptor = Encryptor;
exports.Decryptor = Decryptor;
