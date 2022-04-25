#!/usr/bin/env node

import * as stream from 'stream';
import * as net from 'net';
import * as http from 'http';
import { WebSocketServer, createWebSocketStream } from 'ws';
import { config } from './config';
import { Logger } from './logger';
import { Address, parseAddressFromSocks5Head } from './utils';

const logger = new Logger('ss-server');
const timeout = (config.timeout || 300) * 1000;

const server = http.createServer();
const wss = new WebSocketServer({ server });

wss.on('connection', function connection(ws) {
  let tunnel: stream.Duplex;

  function handleProxy(address: Address) {
    const { port, host, headLeft } = address;

    // connect to real remote
    const proxy = net.createConnection(port, host);
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
      if (headLeft) proxy.write(headLeft);

      tunnel.pipe(proxy);
      proxy.pipe(tunnel);
    });
  }

  ws.once('message', async function message(head: Buffer) {
    tunnel = createWebSocketStream(ws);

    let address: Address;
    try {
      address = await parseAddressFromSocks5Head(head);
    } catch (err) {
      logger.error(err);
      return;
    }

    logger.info('begin proxy', address.info());

    tunnel.on('close', () => {
      logger.info('websocket tunnel close:', address.info());
    });

    tunnel.on('error', (err) => {
      if (err.message.includes('WebSocket is not open')) {
        logger.warn('websocket tunnel error:', address.info(), err.message);
      } else {
        logger.error('websocket tunnel error:', address.info(), err);
      }
    });

    handleProxy(address);
  });
});

server.listen(config.server_port, () => {
  logger.info('ss websocket server listen at %s', config.server_port);
});
