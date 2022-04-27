import CacheableLookup from 'cacheable-lookup';
import * as ipv6 from './ipv6';
import * as util from 'util';
import { Logger } from './logger';

const cacheable = new CacheableLookup();
const logger = new Logger('utils');

type ATYP = 'ipv4' | 'ipv6' | 'domain';

export class Address {
  static count = 0;

  id: number;
  type: ATYP;
  host: string;
  port: number;
  domain: string;
  headLeft: Buffer;

  constructor() {
    this.id = ++Address.count;
  }

  info() {
    return util.format('address<%s>: %s %s:%s', this.id, this.domain, this.host, this.port);
  }
}

//   +------+----------+----------+
//   | ATYP | DST.ADDR | DST.PORT |
//   +------+----------+----------+
//   |  1   | Variable |    2     |
//   +------+----------+----------+
export async function parseAddressFromSocks5Head(head: Buffer, dnslookup = true): Promise<Address> {
  const address = new Address();

  const headLen = head.length;
  let type: ATYP;
  let host = '';
  let port = 0;
  let domain = '';
  let remainDataIndex = -1;

  if (head[0] === 0x01) {
    // ipv4
    if (head.length < 7) {
      throw new Error('invalid ipv4 data');
    }
    type = 'ipv4';
    host = `${head[1]}.${head[2]}.${head[3]}.${head[4]}`;
    port = (head[5] << 8) | head[6];
    if (headLen > 7) remainDataIndex = 7;
  } else if (head[0] === 0x03) {
    // domain
    const domainLen = head[1];
    if (headLen < 4 + domainLen) {
      throw new Error('invalid domain data');
    }
    type = 'domain';
    domain = head.toString('ascii', 2, 2 + domainLen);
    port = (head[2 + domainLen] << 8) | head[3 + domainLen];
    if (headLen > 4 + domainLen) remainDataIndex = 4 + domainLen;
  } else if (head[0] === 0x04) {
    // ipv6
    if (headLen < 19) {
      throw new Error('invalid ipv6 data');
    }
    type = 'ipv6';
    host = ipv6.toStr(head.slice(1, 17));
    port = (head[17] << 8) | head[18];
    if (headLen > 19) remainDataIndex = 19;
  } else {
    throw new Error(`ATYP ${head[0]} not support`);
  }

  // find ip by dns
  if (domain && dnslookup) {
    const start = Date.now();
    try {
      const resp = await cacheable.lookupAsync(domain);
      host = resp.address;
    } finally {
      logger.info('lookup %s:%s cost %s ms', address.id, domain, Date.now() - start);
    }
  }

  const headLeft = remainDataIndex > -1 ? head.slice(remainDataIndex) : null;

  address.type = type;
  address.host = host;
  address.port = port;
  address.domain = domain;
  address.headLeft = headLeft;
  return address;
}
