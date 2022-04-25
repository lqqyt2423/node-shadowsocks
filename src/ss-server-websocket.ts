#!/usr/bin/env node

import * as stream from 'stream';
import * as net from 'net';
import * as http from 'http';
import { WebSocketServer, createWebSocketStream } from 'ws';
import { config } from './config';
import { Encryptor, Decryptor } from './encrypt';
import { Logger } from './logger';
import { Address, parseAddressFromSocks5Head } from './utils';

const logger = new Logger('ss-server');
const timeout = (config.timeout || 300) * 1000;

const server = http.createServer();
const wss = new WebSocketServer({ server });

wss.on('connection', function connection(ws) {
  let proxy: net.Socket;
  let address: Address;
  const tunnel: stream.Duplex = createWebSocketStream(ws);

  tunnel.on('close', () => {
    logger.info('websocket tunnel close:', address?.info());
  });

  tunnel.on('error', (err) => {
    if (err.message.includes('WebSocket is not open')) {
      logger.warn('websocket tunnel error:', address?.info(), err.message);
    } else {
      logger.error('websocket tunnel error:', address?.info(), err);
    }
  });

  const decryptor = new Decryptor(config.method, config.password, { emitFirstPayload: true });

  decryptor.on('error', (err) => {
    logger.error('decryptor error', err);
    if (proxy && !proxy.destroyed) proxy.destroy();
    ws.close();
  });

  function handleProxy() {
    const { port, host, headLeft } = address;

    // connect to real remote
    proxy = net.createConnection(port, host);
    proxy.setNoDelay();
    proxy.setTimeout(timeout);

    proxy.on('error', (err) => {
      if (['ETIMEDOUT', 'ECONNRESET'].includes((err as any).code)) {
        logger.warn('proxy error', address.info(), err.message);
      } else {
        logger.error('proxy error', address.info(), err);
      }

      if (!proxy.destroyed) proxy.destroy();
      ws.close();
    });

    proxy.on('timeout', () => {
      logger.warn('proxy timeout', address.info());
      proxy.end();
      ws.close();
    });

    proxy.once('connect', () => {
      const encryptor = new Encryptor(config.method, config.password);
      proxy.pipe(encryptor).pipe(tunnel);

      if (headLeft) proxy.write(headLeft);

      decryptor.resume();
    });
  }

  decryptor.once('firstPayload', async (head: Buffer) => {
    decryptor.pause();

    try {
      address = await parseAddressFromSocks5Head(head);
    } catch (err) {
      logger.error(err);
      return;
    }
    logger.info('begin proxy', address.info());
    handleProxy();
  });

  decryptor.on('data', (chunk) => {
    proxy.write(chunk);
  });

  decryptor.on('end', () => {
    proxy.end();
  });

  tunnel.pipe(decryptor);
});

server.listen(config.server_port, () => {
  logger.info('ss websocket server listen at %s', config.server_port);
});
