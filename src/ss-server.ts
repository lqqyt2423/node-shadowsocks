#!/usr/bin/env node

import * as net from 'net';
import { config, IConfig, Method } from './config';
import { Encryptor, Decryptor } from './encrypt';
import { Logger } from './logger';
import { IAddress, parseAddressFromSocks5Head } from './utils';

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
    this.socket.on('error', (err) => {
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

  async parseAddress(head: Buffer) {
    let address: IAddress;
    try {
      address = await parseAddressFromSocks5Head(head);
    } catch (err) {
      this.logger.error(err);
      this.socket.end();
      return;
    }

    logger.info('address: %s %s:%s', address.domain, address.host, address.port);

    this.handleProxy(address.port, address.host, address.headLeft);
  }

  handleProxy(port: number, host: string, headLeft: Buffer) {
    // connect to real remote
    const proxy = (this.proxy = net.createConnection(port, host));
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

      if (headLeft) proxy.write(headLeft);

      this.decryptor.resume();
    });
  }

  async handle() {
    this.decryptor.once('firstPayload', (payload: Buffer) => {
      this.decryptor.pause();
      this.parseAddress(payload);
    });

    this.decryptor.on('data', (chunk) => {
      this.proxy.write(chunk);
    });

    this.decryptor.on('end', () => {
      this.proxy.end();
    });

    this.socket.pipe(this.decryptor);
  }
}

net
  .createServer((socket) => {
    new SocketHandler(socket, { logger, ...config }).handle();
  })
  .listen(config.server_port, () => {
    logger.info('ss server listen at %s', config.server_port);
  });

process.on('uncaughtException', (err) => {
  logger.warn('uncaughtException');
  logger.error(err);
});

process.on('unhandledRejection', (err) => {
  logger.warn('unhandledRejection');
  logger.error(err);
});
