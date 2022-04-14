#!/usr/bin/env node

import * as stream from 'stream';
import * as util from 'util';
import * as net from 'net';
import * as dns from 'dns';
import * as http from 'http';
import { WebSocketServer, createWebSocketStream } from 'ws';
import { config } from './config';
import { Logger } from './logger';
import * as ipv6 from './ipv6';

const logger = new Logger('ss-server');
const timeout = (config.timeout || 300) * 1000;

const server = http.createServer();
const wss = new WebSocketServer({ server });

wss.on('connection', function connection(ws) {
  let tunnel: stream.Duplex;

  function handleProxy(port: number, host: string, firstProxyPayload: Buffer) {
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
      if (firstProxyPayload) proxy.write(firstProxyPayload);

      tunnel.pipe(proxy);
      proxy.pipe(tunnel);
    });
  }

  ws.once('message', async function message(rawAddr: Buffer) {
    const rawAddrLen = rawAddr.length;
    let dstHost: string;
    let dstPort: number;
    let isDomain = false;
    let remainDataIndex = -1;
    if (rawAddr[0] === 0x01) {
      // ipv4
      if (rawAddr.length < 7) {
        logger.warn('invalid ipv4 data');
        return;
      }
      dstHost = `${rawAddr[1]}.${rawAddr[2]}.${rawAddr[3]}.${rawAddr[4]}`;
      dstPort = (rawAddr[5] << 8) | rawAddr[6];
      if (rawAddrLen > 7) remainDataIndex = 7;
    } else if (rawAddr[0] === 0x03) {
      // domain
      const domainLen = rawAddr[1];
      if (rawAddrLen < 4 + domainLen) {
        logger.warn('invalid domain data');
        return;
      }
      isDomain = true;
      dstHost = rawAddr.toString('ascii', 2, 2 + domainLen);
      logger.info('domain:', dstHost);
      dstPort = (rawAddr[2 + domainLen] << 8) | rawAddr[3 + domainLen];
      if (rawAddrLen > 4 + domainLen) remainDataIndex = 4 + domainLen;
    } else if (rawAddr[0] === 0x04) {
      // ipv6
      if (rawAddrLen < 19) {
        logger.warn('invalid ipv6 data');
        return;
      }
      dstHost = ipv6.toStr(rawAddr.slice(1, 17));
      dstPort = (rawAddr[17] << 8) | rawAddr[18];
      if (rawAddrLen > 19) remainDataIndex = 19;
    } else {
      logger.warn(`ATYP ${rawAddr[0]} not support`);
      return;
    }

    // find ip by dns
    if (isDomain) {
      try {
        const ips = await util.promisify(dns.resolve4)(dstHost);
        dstHost = ips[0];
      } catch (err) {
        logger.warn('dns error');
        logger.error(err);
        return;
      }
    }

    logger.info('address: %s:%s', dstHost, dstPort);

    tunnel = createWebSocketStream(ws);
    tunnel.on('error', (err) => {
      logger.error('websocket tunnel error:', err, dstPort, dstPort);
    });

    const firstProxyPayload = remainDataIndex > -1 ? rawAddr.slice(remainDataIndex) : null;
    handleProxy(dstPort, dstHost, firstProxyPayload);
  });
});

server.listen(config.server_port, () => {
  logger.info('ss websocket server listen at %s', config.server_port);
});
