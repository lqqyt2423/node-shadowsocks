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
        const startIndex = (i - 1) * MAX_PAYLOAD;
        const payload = chunk.slice(startIndex, startIndex + payloadLen);

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
        cipher2.update(payload).copy(buf, 18);
        cipher2.final();
        cipher2.getAuthTag().copy(buf, payloadLen + 18);
        increase(this.nonce);

        bufs.push(buf);
      }

      return times === 1 ? bufs[0] : Buffer.concat(bufs, len + 34 * times);
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
    this.isGotSalt = false;
    this.nonce = Buffer.alloc(12);

    this.salt = null;
    this.key = null;

    // will emit "firstPayload" event but not transform firstPayload
    this.emitFirstPayload = options.emitFirstPayload || false;
    this._emitedFirstPayload = false;
    this._firstPayloads = this.emitFirstPayload ? [] : null;

    // unhandled buffer last time
    this._buf = null;
    this._state = 1;
    this._payloadLen = 0;
    this._handledPayloadLen = 0;
    this._cipher2 = null;
  }

  // after got salt, handle payload state:
  // 1                                    2                  3            4
  // 1 - only begin, not have _buf
  // [encrypted payload length][length tag][encrypted payload][payload tag]
  update(chunk) {
    if (this._buf) {
      chunk = Buffer.concat([this._buf, chunk]);
      this._buf = null;
    }

    if (!this.isGotSalt) {
      if (chunk.length < this.saltLen) throw new Error('invalid salt');
      this.salt = chunk.slice(0, this.saltLen);
      this.key = hkdf(this.mainkey, this.keyLen, { salt: this.salt, info: 'ss-subkey', hash: 'sha1' });
      this.isGotSalt = true;
      if (chunk.length === this.saltLen) return;
      return this.update(chunk.slice(this.saltLen));
    }

    if (this._state === 1 || this._state === 2) {
      this._state = 2;

      // [encrypted payload length][length tag] = 2 + 16
      if (chunk.length < 18) {
        this._buf = chunk;
        return;
      }

      const cipher1 = crypto.createDecipheriv(this.method, this.key, this.nonce, { authTagLength: 16 });
      cipher1.setAuthTag(chunk.slice(2, 18));
      const lenBuf = cipher1.update(chunk.slice(0, 2));
      cipher1.final();
      increase(this.nonce);
      this._payloadLen = lenBuf.readUInt16BE();
      if (this._payloadLen > MAX_PAYLOAD) throw new Error('invalid payload len');

      this._state = 3;

      if (chunk.length === 18) return;
      return this.update(chunk.slice(18));
    }

    if (this._state === 3) {
      if (!this._cipher2) {
        this._cipher2 = crypto.createDecipheriv(this.method, this.key, this.nonce, { authTagLength: 16 });
      }

      if (chunk.length + this._handledPayloadLen < this._payloadLen) {
        const transed = this._cipher2.update(chunk);
        this._handledPayloadLen += chunk.length;

        if (this.emitFirstPayload && !this._emitedFirstPayload) {
          this._firstPayloads.push(transed);
          return;
        }

        this.push(transed);
        return;
      }

      this._state = 4;
      const leftLen = this._payloadLen - this._handledPayloadLen;
      const transed = this._cipher2.update(chunk.slice(0, leftLen));
      this._handledPayloadLen = this._payloadLen;

      if (this.emitFirstPayload && !this._emitedFirstPayload) {
        this._firstPayloads.push(transed);
        if (leftLen === chunk.length) return;
        return this.update(chunk.slice(leftLen));
      }

      this.push(transed);
      if (leftLen === chunk.length) return;
      return this.update(chunk.slice(leftLen));
    }

    // state 4
    if (chunk.length < 16) {
      this._buf = chunk;
      return;
    }
    this._cipher2.setAuthTag(chunk.slice(0, 16));
    this._cipher2.final();
    increase(this.nonce);

    this._cipher2 = null;
    this._state = 1;
    this._payloadLen = 0;
    this._handledPayloadLen = 0;

    if (this.emitFirstPayload && !this._emitedFirstPayload) {
      this.emit('firstPayload', Buffer.concat(this._firstPayloads));
      this._emitedFirstPayload = true;
      this._firstPayloads = null;
      if (chunk.length === 16) return;
      return this.update(chunk.slice(16));
    }

    if (chunk.length === 16) return;
    return this.update(chunk.slice(16));
  }

  _transform(chunk, encoding, callback) {
    try {
      this.update(chunk);
      callback();
    } catch (err) {
      callback(err);
    }
  }

  _flush(callback) {
    if (this._state !== 1) {
      callback(new Error('invalid data'));
    } else {
      callback();
    }
  }
}

exports.cipherInfoMap = cipherInfoMap;
exports.Encryptor = Encryptor;
exports.Decryptor = Decryptor;
