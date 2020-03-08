#!/usr/bin/env node

'use strict';

const net = require('net');
const dns = require('dns');
const util = require('util');
const ipv6 = require('../ipv6');
const config = require('../config');
const { Encryptor, Decryptor } = require('../encrypt');
const logger = console;

class SocketHandler {
  constructor(socket, options = {}) {
    this.socket = socket;
    this.logger = options.logger || console;
    this.timeout = (options.timeout || 300) * 1000;
    this.cipherMethod = options.method;
    this.cipherPassword = options.password;
    this.decryptor = new Decryptor(this.cipherMethod, this.cipherPassword, { emitFirstPayload: true });

    this.proxy = null;
    this._beforeProxyBuffer = Buffer.allocUnsafe(0);
    this._proxyOk = false;
    this._decryptorEnd = false;

    this.init();
  }

  init() {
    this.socket.setTimeout(this.timeout);
    this.socket.on('error', err => {
      this.logger.warn('socket error');
      this.logger.error(err);
      if (!this.socket.destroyed) this.socket.destroy();
    });

    this.socket.on('timeout', () => {
      this.logger.warn('socket timeout');
      this.socket.end();
    });

    this.decryptor.on('error', (err) => {
      this.logger.warn('decryptor error');
      this.logger.error(err);
      this.socket.end();
      if (this.proxy) this.proxy.end();
    });
  }

  async parseAddress(rawAddr) {
    const rawAddrLen = rawAddr.length;
    let dstHost, dstPort;
    let isDomain = false;
    let remainDataIndex = -1;
    if (rawAddr[0] === 0x01) { // ipv4
      if (rawAddr.length < 7) {
        this.logger.warn('invalid ipv4 data');
        this.socket.end();
        return;
      }
      dstHost = `${rawAddr[1]}.${rawAddr[2]}.${rawAddr[3]}.${rawAddr[4]}`;
      dstPort = (rawAddr[5] << 8) | rawAddr[6];
      if (rawAddrLen > 7) remainDataIndex = 7;
    }
    else if (rawAddr[0] === 0x03) { // domain
      const domainLen = rawAddr[1];
      if (rawAddrLen < 4 + domainLen) {
        this.logger.warn('invalid domain data');
        this.socket.end();
        return;
      }
      isDomain = true;
      dstHost = rawAddr.toString('ascii', 2, 2 + domainLen);
      this.logger.info('domain:', dstHost);
      dstPort = (rawAddr[2 + domainLen] << 8) | rawAddr[3 + domainLen];
      if (rawAddrLen > 4 + domainLen) remainDataIndex = 4 + domainLen;
    }
    else if (rawAddr[0] === 0x04) { // ipv6
      if (rawAddrLen < 19) {
        this.logger.warn('invalid ipv6 data');
        this.socket.end();
        return;
      }
      dstHost = ipv6.toStr(rawAddr.slice(1, 17));
      dstPort = (rawAddr[17] << 8) | rawAddr[18];
      if (rawAddrLen > 19) remainDataIndex = 19;
    }
    else {
      this.logger.warn(`ATYP ${rawAddr[0]} not support`);
      this.socket.end();
      return;
    }

    // find ip by dns
    if (isDomain) {
      try {
        const ips = await util.promisify(dns.resolve4)(dstHost);
        dstHost = ips[0];
      } catch (err) {
        this.logger.warn('dns error');
        this.logger.error(err);
        this.socket.end();
        return;
      }
    }

    this.logger.info('address: %s:%s', dstHost, dstPort);

    const firstProxyPayload = remainDataIndex > -1 ? rawAddr.slice(remainDataIndex) : null;
    this.handleProxy(dstPort, dstHost, firstProxyPayload);
  }

  handleProxy(port, host, firstProxyPayload) {
    // connect to real remote
    const proxy = this.proxy = net.createConnection(port, host);
    proxy.setTimeout(this.timeout);

    proxy.on('error', (err) => {
      this.logger.warn('proxy error');
      this.logger.error(err);
      if (!proxy.destroyed) proxy.destroy();
      this.socket.end();
    });

    proxy.on('timeout', () => {
      this.logger.warn('proxy timeout');
      proxy.end();
      this.socket.end();
    });

    proxy.once('connect', () => {
      const encryptor = new Encryptor(this.cipherMethod, this.cipherPassword);
      proxy.pipe(encryptor).pipe(this.socket);

      if (firstProxyPayload) proxy.write(firstProxyPayload);
      if (this._beforeProxyBuffer.length) proxy.write(this._beforeProxyBuffer);
      this._beforeProxyBuffer = null;
      this._proxyOk = true;
      if (this._decryptorEnd) proxy.end();
    });
  }

  async handle() {
    this.decryptor.once('firstPayload', this.parseAddress.bind(this));

    this.decryptor.on('data', chunk => {
      if (this._proxyOk) {
        this.proxy.write(chunk);
      } else {
        this._beforeProxyBuffer = Buffer.concat([this._beforeProxyBuffer, chunk]);
      }
    });

    this.decryptor.on('end', () => {
      if (this._proxyOk) {
        this.proxy.end();
      } else {
        this._decryptorEnd = true;
      }
    });

    this.socket.pipe(this.decryptor);
  }
}

net.createServer(socket => {
  new SocketHandler(socket, { logger, ...config }).handle();
}).listen(config.server_port, config.server, () => {
  logger.info('ss server listen at %s:%s', config.server, config.server_port);
});

process.on('uncaughtException', err => {
  logger.warn('uncaughtException');
  logger.error(err);
});

process.on('unhandledRejection', err => {
  logger.warn('unhandledRejection');
  logger.error(err);
});
