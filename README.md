# node-shadowsocks

## bench

```
型号名称：	MacBook Pro
型号标识符：	MacBookPro11,4
处理器名称：	Intel Core i7
处理器速度：	2.2 GHz
处理器数目：	1
核总数：	4
L2 缓存（每个核）：	256 KB
L3 缓存：	6 MB
超线程技术：	已启用
内存：	16 GB
```

```
https://github.com/v2ray/experiments

direct
loadgen --port 10002 --amount 1 --concurrency 10
speed: 1700-2500 MB/s

go-shadowsocks2
aes-256-gcm
loadgen --port 1080 --amount 1 --concurrency 10 --type socks --remoteport 10002
speed: 640 MB/s
memory: 4M

this node-shadowsocks 1 instance
aes-256-gcm
loadgen --port 1080 --amount 1 --concurrency 10 --type socks --remoteport 10002
speed: 180-220 MB/s
memory: 30-50M


go-shadowsocks2
aes-256-gcm
loadgen --port 1080 --amount 1 --concurrency 20 --type socks --remoteport 10002
speed: 560 MB/s
memory: 5M

this node-shadowsocks 1 instance
aes-256-gcm
loadgen --port 1080 --amount 1 --concurrency 20 --type socks --remoteport 10002
speed: 200 MB/s
memory: 30-50M
```
