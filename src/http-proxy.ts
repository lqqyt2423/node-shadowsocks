import * as net from 'net';
import { URL } from 'url';
import * as http from 'http';
import { Logger } from './logger';

const logger = new Logger('http-proxy');

class Socks5Client {
  private socksHost: string;
  private socksPort: number;

  constructor(socksHost: string, socksPort: number) {
    this.socksHost = socksHost;
    this.socksPort = socksPort;
  }

  public async connect(host: string, port: number): Promise<net.Socket> {
    return await new Promise((resolve, reject) => {
      const socket = net.createConnection({ port: this.socksPort, host: this.socksHost });

      socket.once('error', reject);

      const consume: () => Promise<Buffer> = () => {
        return new Promise((cb) => {
          socket.once('data', cb);
        });
      };

      socket.once('connect', async () => {
        socket.write(Buffer.from([0x05, 0x01, 0x00]));

        const res = await consume();
        if (!Buffer.from([0x05, 0x00]).equals(res)) {
          socket.destroy();
          return reject(new Error('error socks5 endpoint 1'));
        }

        const portBuf = Buffer.allocUnsafe(2);
        portBuf.writeInt16BE(Number(port));
        const data = Buffer.concat([Buffer.from([0x05, 0x01, 0x00, 0x03, Buffer.byteLength(host)]), Buffer.from(host), portBuf]);
        socket.write(data);

        const res2 = await consume();
        if (res2[0] !== 5 || res2[1] !== 0) {
          socket.destroy();
          return reject(new Error('error socks5 endpoint 2'));
        }

        resolve(socket);
      });
    });
  }
}

interface Socks5AgentOptions extends http.AgentOptions {
  socksHost: string;
  socksPort: number;
}

class Socks5Agent extends http.Agent {
  private socks5Client: Socks5Client;

  constructor(opts: Socks5AgentOptions) {
    const { socksHost, socksPort, ...leftOpts } = opts;
    super(leftOpts);

    this.socks5Client = new Socks5Client(socksHost, socksPort);
  }

  public createConnection(options: http.ClientRequestArgs, oncreate: (err: Error, socket: net.Socket) => void): net.Socket {
    if (!options.hostname || !options.port) {
      oncreate(new Error('no hostname or port'), null);
      return null;
    }

    this.socks5Client
      .connect(options.hostname, Number(options.port))
      .then((socket) => {
        oncreate(null, socket);
      })
      .catch((err) => {
        oncreate(err, null);
      });

    return null;
  }
}

export class HTTPProxy {
  private port: number;
  private server: http.Server;
  private agent: http.Agent;
  private socks5Client: Socks5Client;

  constructor(options: { port: number; socksHost: string; socksPort: number }) {
    this.port = options.port;
    this.agent = new Socks5Agent({ socksHost: options.socksHost, socksPort: options.socksPort });
    this.socks5Client = new Socks5Client(options.socksHost, options.socksPort);
    this.server = this.createServer();
  }

  private createServer() {
    const server = http.createServer();

    server.on('request', (req: http.IncomingMessage, res: http.ServerResponse) => {
      logger.info('http %s %s', req.method, req.url);

      const url = new URL(req.url);
      const proxyClient = http.request(
        {
          agent: this.agent,
          hostname: url.hostname,
          port: url.port || 80,
          method: req.method,
          path: url.pathname + url.search,
          headers: req.headers,
        },
        (proxyRes) => {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
          proxyRes.pipe(res);
        }
      );

      proxyClient.on('error', (err) => {
        logger.error('proxyClient error', err);
        if (!res.headersSent) res.writeHead(502);
        if (!res.writableEnded) res.end();
      });

      req.pipe(proxyClient);
    });

    server.on('connect', async (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => {
      logger.info('https %s', req.url);
      const url = new URL('https://' + req.url);
      const hostname = url.hostname;
      const port = Number(url.port) || 443;

      let clientSocket: net.Socket;
      try {
        clientSocket = await this.socks5Client.connect(hostname, port);
      } catch (err) {
        socket.destroy();
        logger.error('clientSocket error', err);
        return;
      }

      socket.on('error', (err) => {
        logger.error('socket error', err);
      });

      clientSocket.on('error', (err) => {
        logger.error('clientSocket error', err);
      });

      socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      clientSocket.write(head);

      clientSocket.pipe(socket);
      socket.pipe(clientSocket);
    });

    return server;
  }

  public start() {
    this.server.on('error', (err) => {
      logger.info('http proxy server error:', err);
    });

    this.server.listen(this.port, () => {
      logger.info('http proxy listen at %s', this.port);
    });
  }
}
