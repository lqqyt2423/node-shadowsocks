import net from 'net';
import { URL } from 'url';
import http from 'http';
import { logger } from './logger';

interface Socks5AgentOptions extends http.AgentOptions {
  socksHost: string;
  socksPort: number;
}

class Socks5Agent extends http.Agent {
  private socksHost: string;
  private socksPort: number;

  constructor(opts: Socks5AgentOptions) {
    const { socksHost, socksPort, ...leftOpts } = opts;
    super(leftOpts);

    this.socksHost = socksHost;
    this.socksPort = socksPort;
  }

  public createConnection(options: http.ClientRequestArgs, oncreate: (err: Error, socket: net.Socket) => void): net.Socket {
    if (!options.hostname || !options.port) {
      oncreate(new Error('no hostname or port'), null);
      return null;
    }

    const socket = net.createConnection({ port: this.socksPort, host: this.socksHost });

    socket.on('error', err => {
      oncreate(err, null);
    });

    const consume: () => Promise<Buffer> = () => {
      return new Promise(resolve => {
        socket.once('data', resolve);
      });
    };

    socket.once('connect', async () => {
      socket.write(Buffer.from([0x05, 0x01, 0x00]));

      const res = await consume();
      if (!Buffer.from([0x05, 0x00]).equals(res)) {
        socket.destroy();
        return oncreate(new Error('error socks5 endpoint 1'), null);
      }

      const portBuf = Buffer.allocUnsafe(2);
      portBuf.writeInt16BE(Number(options.port));
      const data = Buffer.concat([
        Buffer.from([0x05, 0x01, 0x00, 0x03, Buffer.byteLength(options.hostname)]),
        Buffer.from(options.hostname),
        portBuf,
      ]);
      socket.write(data);

      const res2 = await consume();
      if (res2[0] !== 5 || res2[1] !== 0) {
        socket.destroy();
        return oncreate(new Error('error socks5 endpoint 2'), null);
      }

      oncreate(null, socket);
    });

    return null;
  }
}

export class HTTPProxy {
  private port: number;
  private server: http.Server;
  private agent: http.Agent;

  constructor(options: {
    port: number;
    socksHost: string;
    socksPort: number;
  }) {
    this.port = options.port;
    this.agent = new Socks5Agent({ socksHost: options.socksHost, socksPort: options.socksPort });
    this.server = this.createServer();
  }

  private createServer() {
    const server = http.createServer();

    server.on('request', (req: http.IncomingMessage, res: http.ServerResponse) => {
      logger.info('http %s %s', req.method, req.url);

      const url = new URL(req.url);
      const proxyClient = http.request({
        agent: this.agent,
        hostname: url.hostname,
        port: url.port || 80,
        method: req.method,
        path: url.pathname + url.search,
        headers: req.headers,
      }, (proxyRes) => {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
      });

      req.pipe(proxyClient);
    });

    return server;
  }

  public start() {
    this.server.listen(this.port, () => {
      logger.info('http proxy listen at %s', this.port);
    });
  }
}
