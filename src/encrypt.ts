import { Transform, TransformCallback } from 'stream';
import crypto from 'crypto';
import hkdf from 'futoin-hkdf';
import { cipherInfoMap, Method } from './config';

// the maximum size of payload in bytes
const MAX_PAYLOAD = 0x3fff;

function md5(b: crypto.BinaryLike) {
  return crypto.createHash('md5').update(b).digest();
}

// copy from shadowsocks-go evpBytesToKey
function _evpBytesToKey(pwstr: string, keyLen: number) {
  const password = Buffer.from(pwstr);
  const md5Len = 16;
  const cnt = Math.floor((keyLen - 1) / md5Len) + 1;
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

const keyCache = new Map<string, Buffer>();
function evpBytesToKey(password: string, keyLen: number) {
  const cacheKey = password + keyLen;
  let value = keyCache.get(cacheKey);
  if (value) return value;
  value = _evpBytesToKey(password, keyLen);
  keyCache.set(cacheKey, value);
  return value;
}

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
function increase(nonce: Buffer) {
  for (let i = 0; i < 12; i++) {
    nonce[i] += 1;
    if (nonce[i] !== 0) return;
  }
}

export class Encryptor extends Transform {
  private method: Method;
  private salt: Buffer;
  private key: Buffer;
  private nonce: Buffer;
  private isPutSalt: boolean;

  constructor(method: Method, password: string) {
    super();

    this.method = method;
    const { keyLen, saltLen } = cipherInfoMap[method];
    const mainkey = evpBytesToKey(password, keyLen);
    this.salt = crypto.randomBytes(saltLen);
    this.key = hkdf(mainkey, keyLen, { salt: this.salt, info: 'ss-subkey', hash: 'sha1' });
    this.nonce = Buffer.alloc(12);
    this.isPutSalt = false;
  }

  private update(chunk: Buffer) {
    if (!this.isPutSalt) {
      this.push(this.salt);
      this.isPutSalt = true;
    }

    const len = chunk.length;
    const times = Math.ceil(len / MAX_PAYLOAD);

    for (let i = 1; i <= times; i++) {
      const startIndex = (i - 1) * MAX_PAYLOAD;
      const payloadLen = i === times ? (len - startIndex) : MAX_PAYLOAD;
      const payload = chunk.slice(startIndex, startIndex + payloadLen);

      // [encrypted payload length][length tag][encrypted payload][payload tag]

      const cipher1 = crypto.createCipheriv(this.method as crypto.CipherGCMTypes, this.key, this.nonce, { authTagLength: 16 });
      const lenBuf = Buffer.allocUnsafe(2);
      lenBuf.writeUInt16BE(payloadLen);
      this.push(cipher1.update(lenBuf));
      cipher1.final();
      this.push(cipher1.getAuthTag());
      increase(this.nonce);

      const cipher2 = crypto.createCipheriv(this.method as crypto.CipherGCMTypes, this.key, this.nonce, { authTagLength: 16 });
      this.push(cipher2.update(payload));
      cipher2.final();
      this.push(cipher2.getAuthTag());
      increase(this.nonce);
    }
  }

  _transform(chunk: any, encoding: BufferEncoding, callback: TransformCallback) {
    this.update(chunk);
    callback();
  }
}

export class Decryptor extends Transform {
  private method: Method;
  private keyLen: number;
  private saltLen: number;
  private mainkey: Buffer;
  private isGotSalt: boolean;
  private nonce: Buffer;
  private salt: Buffer;
  private key: Buffer;
  private emitFirstPayload: boolean;
  private _emitedFirstPayload: boolean;
  private _firstPayloads: Buffer[];
  private _buf: Buffer;
  private _state: number;
  private _payloadLen: number;
  private _handledPayloadLen: number;
  private _cipher2: crypto.DecipherGCM;

  constructor(method: Method, password: string, options?: { emitFirstPayload: boolean }) {
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
    this.emitFirstPayload = options?.emitFirstPayload || false;
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
  update(chunk: Buffer) {
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
      chunk = chunk.slice(this.saltLen);
    }

    // eslint-disable-next-line no-constant-condition
    while (true) {
      if (this._state === 1 || this._state === 2) {
        this._state = 2;

        // [encrypted payload length][length tag] = 2 + 16
        if (chunk.length < 18) {
          this._buf = chunk;
          return;
        }

        const cipher1 = crypto.createDecipheriv(this.method as crypto.CipherGCMTypes, this.key, this.nonce, { authTagLength: 16 });
        cipher1.setAuthTag(chunk.slice(2, 18));
        const lenBuf = cipher1.update(chunk.slice(0, 2));
        cipher1.final();
        increase(this.nonce);
        this._payloadLen = lenBuf.readUInt16BE();
        if (this._payloadLen > MAX_PAYLOAD) throw new Error('invalid payload len');

        this._state = 3;

        if (chunk.length === 18) return;
        chunk = chunk.slice(18);
      }

      if (this._state === 3) {
        if (!this._cipher2) {
          this._cipher2 = crypto.createDecipheriv(this.method as crypto.CipherGCMTypes, this.key, this.nonce, { authTagLength: 16 });
        }

        if (chunk.length + this._handledPayloadLen < this._payloadLen) {
          const transed = this._cipher2.update(chunk);
          this._handledPayloadLen += chunk.length;

          if (this.emitFirstPayload && !this._emitedFirstPayload) {
            this._firstPayloads.push(transed);
          } else {
            this.push(transed);
          }

          return;
        }

        this._state = 4;
        const leftLen = this._payloadLen - this._handledPayloadLen;
        const transed = this._cipher2.update(chunk.slice(0, leftLen));
        this._handledPayloadLen = this._payloadLen;

        if (this.emitFirstPayload && !this._emitedFirstPayload) {
          this._firstPayloads.push(transed);
        } else {
          this.push(transed);
        }

        if (leftLen === chunk.length) return;
        chunk = chunk.slice(leftLen);
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
      }

      if (chunk.length === 16) return;
      chunk = chunk.slice(16);
    }
  }

  _transform(chunk: any, encoding: BufferEncoding, callback: TransformCallback) {
    try {
      this.update(chunk);
      callback();
    } catch (err) {
      callback(err);
    }
  }

  _flush(callback: TransformCallback) {
    if (this._state !== 1) {
      callback(new Error('invalid data'));
    } else {
      callback();
    }
  }
}
