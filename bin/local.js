#!/usr/bin/env node

'use strict';

const net = require('net');
const config = require('../config');
const { Encryptor, Decryptor } = require('../encrypt');
const logger = console;

class SocketHandler {
  constructor(socket, options = {}) {
    this.socket = socket;
    this.logger = options.logger || console;
    this.timeout = (options.timeout || 300) * 1000;
    this.server_port = options.server_port;
    this.server = options.server;
    this.cipherMethod = options.method;
    this.cipherPassword = options.password;

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
  }

  consume() {
    return new Promise(resolve => {
      this.socket.once('data', resolve);
    });
  }


  //   +----+----------+----------+
  //   |VER | NMETHODS | METHODS  |
  //   +----+----------+----------+
  //   | 1  |    1     | 1 to 255 |
  //   +----+----------+----------+

  async authentication() {
    const data = await this.consume();
    if (data[0] !== 0x05) {
      this.logger.error('Unsupported SOCKS version: %d', data[0]);
      this.socket.end();
      return true;
    }

    // o  X'00' NO AUTHENTICATION REQUIRED
    // o  X'01' GSSAPI
    // o  X'02' USERNAME/PASSWORD
    // o  X'03' to X'7F' IANA ASSIGNED
    // o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
    // o  X'FF' NO ACCEPTABLE METHODS
    const nmethods = data[1];
    const methods = data.slice(2, 2 + nmethods);
    // only support 0x00
    if (methods.includes(0x00)) {
      this.socket.write(Buffer.from([0x05, 0x00]));
    }
    else {
      this.logger.error('auth methods not support');
      this.socket.end(Buffer.from([0x05, 0xff]));
      return true;
    }
  }


  //   +----+-----+-------+------+----------+----------+
  //   |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
  //   +----+-----+-------+------+----------+----------+
  //   | 1  |  1  | X'00' |  1   | Variable |    2     |
  //   +----+-----+-------+------+----------+----------+

  //   o  X'00' succeeded
  //   o  X'01' general SOCKS server failure
  //   o  X'02' connection not allowed by ruleset
  //   o  X'03' Network unreachable
  //   o  X'04' Host unreachable
  //   o  X'05' Connection refused
  //   o  X'06' TTL expired
  //   o  X'07' Command not supported
  //   o  X'08' Address type not supported
  //   o  X'09' to X'FF' unassigned

  reply(rep) {
    this.socket.write(Buffer.from([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
  }

  async request() {
    // Requests

    //   +----+-----+-------+------+----------+----------+
    //   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    //   +----+-----+-------+------+----------+----------+
    //   | 1  |  1  | X'00' |  1   | Variable |    2     |
    //   +----+-----+-------+------+----------+----------+

    const data = await this.consume();
    if (data[0] != 0x05) {
      this.logger.error('Unsupported SOCKS version: %d', data[0]);
      return this.socket.end();
    }

    // o  CONNECT X'01'
    // o  BIND X'02'
    // o  UDP ASSOCIATE X'03'
    if (data[1] !== 0x01) {
      this.reply(0x07);
      return this.socket.end();
    }

    if (data[2] !== 0x00) this.logger.warn('RESERVED should be 0x00');

    let rawAddr;
    switch (data[3]) {
    case 0x01: // ipv4
      // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
      rawAddr = data.slice(3, 10);
      break;
    case 0x03: // domain
    {
      const domainLen = data[4];
      // 3 + 1addrType + 1addrLen + 2port, plus addrLen
      rawAddr = data.slice(3, 7 + domainLen);
      break;
    }
    case 0x04: // ipv6
      // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
      rawAddr = data.slice(3, 22);
      break;
    default:
      this.logger.error(`ATYP ${data[3]} not support`);
      this.reply(0x08);
      return this.socket.end();
    }

    let replyed = false;
    // connect to ss-server
    const proxy = net.createConnection(this.server_port, this.server);
    proxy.setTimeout(this.timeout);

    proxy.on('error', (err) => {
      this.logger.warn('proxy error');
      this.logger.error(err);
      if (!replyed) this.reply(0x05);
      if (!proxy.destroyed) proxy.destroy();
      this.socket.end();
    });

    proxy.on('timeout', () => {
      this.logger.warn('proxy timeout');
      if (!replyed) this.reply(0x05);
      proxy.end();
      this.socket.end();
    });

    proxy.once('connect', () => {
      this.reply(0x00);
      replyed = true;

      const encryptor = new Encryptor(this.cipherMethod, this.cipherPassword);
      encryptor.pipe(proxy);
      encryptor.write(rawAddr);
      this.socket.pipe(encryptor);

      const decryptor = new Decryptor(this.cipherMethod, this.cipherPassword);
      decryptor.on('error', (err) => {
        this.logger.warn('decryptor error');
        this.logger.error(err);
        this.socket.end();
        proxy.end();
      });
      proxy.pipe(decryptor).pipe(this.socket);
    });
  }

  async handle() {
    const finished = await this.authentication();
    if (finished) return;

    this.request();
  }
}

net.createServer(socket => {
  new SocketHandler(socket, { logger, ...config }).handle();
}).listen(config.local_port, config.local_address, () => {
  logger.info('ss local server listen at %s:%s', config.local_address, config.local_port);
});

process.on('uncaughtException', err => {
  logger.warn('uncaughtException');
  logger.error(err);
});

process.on('unhandledRejection', err => {
  logger.warn('unhandledRejection');
  logger.error(err);
});
