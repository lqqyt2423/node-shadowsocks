#!/usr/bin/env node

import net from 'net';
import dns from 'dns';
import util from 'util';
import * as ipv6 from './ipv6';
import { config, IConfig, Method } from './config';
import { Encryptor, Decryptor } from './encrypt';
import { Logger } from './logger';

const logger = new Logger('ss-server');

interface IOptions extends IConfig {
  logger: Logger;
}

class SocketHandler {
  private socket: net.Socket;
  private logger: Logger;
  private timeout: number;
  private cipherMethod: Method;
  private cipherPassword: string;
  private decryptor: Decryptor;
  private proxy: net.Socket;

  constructor(socket: net.Socket, options: IOptions) {
    this.socket = socket;
    this.logger = options.logger || logger;
    this.timeout = (options.timeout || 300) * 1000;
    this.cipherMethod = options.method;
    this.cipherPassword = options.password;
    this.decryptor = new Decryptor(this.cipherMethod, this.cipherPassword, { emitFirstPayload: true });

    this.proxy = null;

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

  async parseAddress(rawAddr: Buffer) {
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

  handleProxy(port: number, host: string, firstProxyPayload: Buffer) {
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

      this.decryptor.resume();
    });
  }

  async handle() {
    this.decryptor.once('firstPayload', (payload: Buffer) => {
      this.decryptor.pause();
      this.parseAddress(payload);
    });

    this.decryptor.on('data', chunk => {
      this.proxy.write(chunk);
    });

    this.decryptor.on('end', () => {
      this.proxy.end();
    });

    this.socket.pipe(this.decryptor);
  }
}

net.createServer(socket => {
  new SocketHandler(socket, { logger, ...config }).handle();
}).listen(config.server_port, () => {
  logger.info('ss server listen at %s', config.server_port);
});

process.on('uncaughtException', err => {
  logger.warn('uncaughtException');
  logger.error(err);
});

process.on('unhandledRejection', err => {
  logger.warn('unhandledRejection');
  logger.error(err);
});
