# node-shadowsocks

## bench

```
https://github.com/v2ray/experiments

direct
loadgen --port 10002 --amount 1 --concurrency 10
speed: 1700-2500 MB/s

go-shadowsocks2
aes-256-gcm
loadgen --port 1080 --amount 1 --concurrency 10 --type socks --remoteport 10002
speed: 240-260 MB/s
memory: 4M

this node-shadowsocks
aes-256-gcm
loadgen --port 1080 --amount 1 --concurrency 10 --type socks --remoteport 10002
speed: 150 MB/s
memory: 50-90M


go-shadowsocks2
aes-256-gcm
loadgen --port 1080 --amount 1 --concurrency 20 --type socks --remoteport 10002
speed: 240-260 MB/s
memory: 5M

this node-shadowsocks
aes-256-gcm
loadgen --port 1080 --amount 1 --concurrency 20 --type socks --remoteport 10002
speed: 120 MB/s
memory: 50-90M
```
