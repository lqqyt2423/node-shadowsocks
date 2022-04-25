#!/usr/bin/env node

import * as stream from 'stream';
import * as net from 'net';
import { WebSocket, createWebSocketStream } from 'ws';
import { config, IConfig, Method } from './config';
import { Logger } from './logger';
import { Encryptor, Decryptor } from './encrypt';
import { HTTPProxy } from './http-proxy';
import { Address, parseAddressFromSocks5Head } from './utils';

const logger = new Logger('ss-local');

interface IOptions extends IConfig {
  logger: Logger;
}

const remoteAddr = (socket: net.Socket) => {
  return `${socket.remoteAddress || ''}:${socket.remotePort || ''}`;
};

class SocketHandler {
  private socket: net.Socket;
  private tunnel: stream.Duplex;
  private logger: Logger;
  private timeout: number;
  private server_port: number;
  private server: string;
  private cipherMethod: Method;
  private cipherPassword: string;
  private address: Address;

  constructor(socket: net.Socket, options: IOptions) {
    this.socket = socket;
    this.tunnel = null;
    this.logger = options.logger || logger;
    this.timeout = (options.timeout || 300) * 1000;
    this.server_port = options.server_port;
    this.server = options.server;
    this.cipherMethod = options.method;
    this.cipherPassword = options.password;

    this.init();
  }

  init() {
    this.socket.setNoDelay();
    this.socket.setTimeout(this.timeout);

    this.socket.on('timeout', () => {
      this.logger.warn('socket timeout', this.address?.info(), remoteAddr(this.socket));
      this.socket.destroy();
    });

    this.socket.on('error', (err) => {
      logger.error('socket error:', remoteAddr(this.socket), err);
    });

    this.socket.on('close', () => {
      if (this.tunnel && !this.tunnel.destroyed) {
        this.tunnel.destroy();
      }
    });
  }

  consume(): Promise<Buffer> {
    return new Promise((resolve) => {
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
      this.socket.destroy();
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
    } else {
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

  reply(rep: number) {
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
      return this.socket.destroy();
    }

    // o  CONNECT X'01'
    // o  BIND X'02'
    // o  UDP ASSOCIATE X'03'
    if (data[1] !== 0x01) {
      this.reply(0x07);
      return this.socket.destroy();
    }

    if (data[2] !== 0x00) this.logger.warn('RESERVED should be 0x00');

    let head: Buffer;
    switch (data[3]) {
      case 0x01: // ipv4
        // 3(ver+cmd+rsv) + 1addrType + ipv4 + 2port
        head = data.slice(3, 10);
        break;
      case 0x03: {
        // domain
        const domainLen = data[4];
        // 3 + 1addrType + 1addrLen + 2port, plus addrLen
        head = data.slice(3, 7 + domainLen);
        break;
      }
      case 0x04: // ipv6
        // 3(ver+cmd+rsv) + 1addrType + ipv6 + 2port
        head = data.slice(3, 22);
        break;
      default:
        this.logger.error(`ATYP ${data[3]} not support`);
        this.reply(0x08);
        return this.socket.destroy();
    }

    // only for log
    parseAddressFromSocks5Head(head, false)
      .then((address) => {
        this.address = address;
        logger.info('begin proxy', address.info());
      })
      .catch(() => {
        // do nothing
      });

    if (config.tunnel === 'tcp') {
      await this.useTcpTunnel(head);
    } else if (config.tunnel === 'ws' || config.tunnel === 'wss') {
      await this.useWebSocketTunnel(head);
    } else {
      throw new Error('should not be here');
    }
  }

  async handle() {
    const finished = await this.authentication();
    if (finished) return;

    this.request();
  }

  async useTcpTunnel(head: Buffer) {
    const tunnel = net.createConnection(this.server_port, this.server);
    this.tunnel = tunnel;

    tunnel.on('timeout', () => {
      this.logger.warn('tcp tunnel timeout', remoteAddr(this.socket));
      tunnel.destroy();
    });

    tunnel.on('error', (err) => {
      this.logger.error('tcp tunnel error:', remoteAddr(this.socket), err);
    });

    tunnel.on('close', () => {
      if (!this.socket.destroyed) {
        this.socket.destroy();
      }
    });

    await new Promise((resolve) => {
      tunnel.on('connect', resolve);
    });

    tunnel.setNoDelay();
    tunnel.setTimeout(this.timeout);

    this.reply(0x00);

    const encryptor = new Encryptor(this.cipherMethod, this.cipherPassword);
    encryptor.pipe(this.tunnel);
    encryptor.write(head);
    this.socket.pipe(encryptor);

    const decryptor = new Decryptor(this.cipherMethod, this.cipherPassword);
    decryptor.on('error', (err) => {
      this.logger.error('decryptor error:', remoteAddr(this.socket), err);
      this.tunnel.destroy();
    });
    this.tunnel.pipe(decryptor).pipe(this.socket);
  }

  async useWebSocketTunnel(head: Buffer) {
    let endpoint = '';
    if (this.server.startsWith('ws')) {
      endpoint = this.server;
    } else {
      endpoint = `${config.tunnel}://${this.server}:${this.server_port}`;
    }

    const ws = new WebSocket(endpoint);
    const tunnel = createWebSocketStream(ws);
    this.tunnel = tunnel;

    tunnel.on('close', () => {
      this.logger.info('websocket tunnel close:', this.address?.info(), remoteAddr(this.socket));
    });

    tunnel.on('error', (err) => {
      this.logger.error('websocket tunnel error:', this.address?.info(), remoteAddr(this.socket), err);
    });

    this.reply(0x00);

    tunnel.write(head);
    this.socket.pipe(tunnel);
    tunnel.pipe(this.socket);
  }
}

const ssLocalServer = net.createServer((socket) => {
  new SocketHandler(socket, { logger, ...config }).handle();
});

ssLocalServer.on('error', (err) => {
  logger.info('ss local server error:', err);
});

ssLocalServer.listen(config.local_port, () => {
  logger.info('ss local server listen at %s', config.local_port);
});

new HTTPProxy({
  port: config.local_http_port,
  socksHost: config.local_address,
  socksPort: config.local_port,
}).start();
