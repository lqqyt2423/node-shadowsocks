import { URL } from 'url';
import http from 'http';
import { logger } from './logger';

export class HTTPProxy {
  private port: number;
  private socksHost: string;
  private socksPort: number;
  private server: http.Server;

  constructor(options: {
    port: number;
    socksHost: string;
    socksPort: number;
  }) {
    this.port = options.port;
    this.socksHost = options.socksHost;
    this.socksPort = options.socksPort;
    this.server = this.createServer();
  }

  private createServer() {
    const server = http.createServer();

    server.on('request', (req: http.IncomingMessage, res: http.ServerResponse) => {
      logger.info('http %s %s', req.method, req.url);

      const url = new URL(req.url);
      const proxyClient = http.request({
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
