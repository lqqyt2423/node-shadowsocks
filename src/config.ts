// nonce size: 12, tag size: 16
export const cipherInfoMap = {
  'chacha20-poly1305': { keyLen: 32, saltLen: 32 },
  'aes-256-gcm': { keyLen: 32, saltLen: 32 },
  'aes-192-gcm': { keyLen: 24, saltLen: 24 },
  'aes-128-gcm': { keyLen: 16, saltLen: 16 },
};

export type Method = keyof typeof cipherInfoMap;

export interface IConfig {
  server: string;
  server_port: number;
  local_port: number;
  local_address: string;
  password: string;
  method: Method;
  timeout: number;
  local_http_port: number;
  tunnel: 'tcp' | 'ws' | 'wss';
}

// eslint-disable-next-line @typescript-eslint/no-var-requires
export const config: IConfig = require('../config.json');
