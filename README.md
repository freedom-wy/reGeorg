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


Example
---------
```
$ python reGeorgSocksProxy.py -p 8080 -u http://xxx.xxx.xxx:8080/tunnel/tunnel.jsp
```
