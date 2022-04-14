#!/usr/bin/env node

import * as stream from 'stream';
import * as net from 'net';
import * as http from 'http';
import { WebSocketServer, createWebSocketStream } from 'ws';
import { config } from './config';
import { Logger } from './logger';
import { IAddress, parseAddressFromSocks5Head } from './utils';

const logger = new Logger('ss-server');
const timeout = (config.timeout || 300) * 1000;

const server = http.createServer();
const wss = new WebSocketServer({ server });

wss.on('connection', function connection(ws) {
  let tunnel: stream.Duplex;

  function handleProxy(port: number, host: string, headLeft: Buffer) {
    // connect to real remote
    const proxy = net.createConnection(port, host);
    proxy.setTimeout(timeout);

    proxy.on('error', (err) => {
      logger.warn('proxy error');
      logger.error(err);
      if (!proxy.destroyed) proxy.destroy();
      ws.close();
    });

    proxy.on('timeout', () => {
      logger.warn('proxy timeout');
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

    let address: IAddress;
    try {
      address = await parseAddressFromSocks5Head(head);
    } catch (err) {
      logger.error(err);
      return;
    }

    logger.info('address: %s %s:%s', address.domain, address.host, address.port);

    tunnel.on('error', (err) => {
      logger.error('websocket tunnel error:', address.domain, address.host, address.port, err);
    });

    handleProxy(address.port, address.host, address.headLeft);
  });
});

server.listen(config.server_port, () => {
  logger.info('ss websocket server listen at %s', config.server_port);
});
