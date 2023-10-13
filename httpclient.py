#!/usr/bin/env python3
# coding: utf-8
# Copyright 2016 Abram Hindle, https://github.com/tywtyw2002, and https://github.com/treedust
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Do not use urllib's HTTP GET and POST mechanisms.
# Write your own HTTP GET and POST
# The point is to understand what you have to send and get experience with it

import sys
import socket
import re
# you may use urllib to encode data appropriately
import urllib.parse

# TODO: DEBUG REMOVE
# log = open('log.txt', 'w')

shouldPercentEncode = [ ':', '/', '?', '#', '[', ']', '@', '!', '$', '&', "'", '(', ')', '*', '+', ',', ';', '=', '%', ' ']


def help():
    print("httpclient.py [GET/POST] [URL]\n")

class HTTPResponse(object):
    def __init__(self, code=200, body=""):
        self.code = code
        self.body = body

class HTTPClient(object):
    #def get_host_port(self,url):

    def connect(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        return None

    def get_code(self, data):
        protocol, _, data = data.partition(' ')
        code, _, data = data.partition(' ')
        return int(code)

    def get_headers(self,data):
        headers = []
        _, _, data = data.partition('\n')
        header = "a"
        while header != "":
            header, _, data = data.partition('\r\n')
            headers.append(header)
        return None

    def get_body(self, data):
        left = "a"
        while left.strip() != "":
            left, _, data = data.partition('\n')
        return data
    
    def sendall(self, data):
        self.socket.sendall(data.encode('utf-8'))
        self.socket.shutdown(socket.SHUT_WR)
        
    def close(self):
        self.socket.close()

    # read everything from the socket
    def recvall(self, sock):
        buffer = bytearray()
        done = False
        while not done:
            part = sock.recv(1024)
            #log.write("READING: " + str(part) + "\n")
            if (part):
                buffer.extend(part)
            else:
                done = not part
        return buffer.decode('utf-8')

    def GET(self, url, args=None):

        self.connectToServer(url)

        # Send Request
        req = HTTPRequest("GET", url, {
            "Host" : self.getHost(url),
            "Accept" : "*/*",
            "Connection" : "close",
        })
        if args is not None:
            req.path = req.path + '?' + self.encodeArgs(args)
        self.sendall(req.toPayload())

        #log.write("Sending\n")
        #log.write(req.toPayload())
        #log.write("=====\n\n")

        resp = self.getHTTPResponse()
        self.close()

        return resp

    def POST(self, url, args=None):

        self.connectToServer(url)
        #log.write("Args: " + str(args) + "\n")

        # Send Request
        req = HTTPRequest("POST", url, {
            "Host" : self.getHost(url),
            "Accept" : "*/*",
            "Connection" : "close",
        })
        body = self.encodeArgs(args)
        if body != "":
            req.headers["Content-Type"] = "application/x-www-form-urlencoded"
            req.headers["Content-Length"] = len(bytearray(body, 'utf-8'))
            req.body = body
        else:
            req.headers["Content-Length"] = str(0)

        self.sendall(req.toPayload())

        #log.write("Sending\n")
        #log.write(req.toPayload())
        #log.write("=====\n\n")

        resp = self.getHTTPResponse()
        self.close()

        return resp
    
    def getHTTPResponse(self):
        data = self.recvall(self.socket)

        if data.strip() == "":
            return None
        code = self.get_code(data)
        body = self.get_body(data)

        #log.write("LOG: data\n" + data + "\n")
        #log.write("LOG: Obtained resp code " + str(code) + "\n")
        #log.write("LOG: Obtained resp body\n")
        #log.write(body)
        #log.write('\n')
        #log.write("\n----------------------------------\n\n")

        return HTTPResponse(code, body)
    
    def encodeArgs(self, args = None):
        res = ""
        if args == None:
            return res
        for key, value in args.items():
            res += f"&{self.percentEncode(key)}={self.percentEncode(value)}"
        return res.removeprefix('&')

    def percentEncode(self, str):
        res = ""
        for c in str:
            if c in shouldPercentEncode:
                ascii = ord(c)
                hexVal = hex(ascii)
                res += '%' + hexVal.removeprefix("0x")
            else:
                res += c
        return res 
    
    def connectToServer(self, url):
        host = socket.gethostbyname(self.getHost(url))
        port = self.getPort(url)
        self.connect(host, port)
        
        #log.write("GET/POST " + str(url) + "\n")
        #log.write("LOG: Obtained Host IP: " + host + " Port: " + str(port) + "\n")
        
    def getHost(self, url):
        return urllib.parse.urlparse(url).netloc.split(':')[0]
    
    def getPort(self, url):
        netloc = urllib.parse.urlparse(url).netloc.split(':')
        if len(netloc) > 1:
            port = int(netloc[1])
        else:
            # ASSUME HTTP/1.1 only; otherwise, it's outside of assignment spec
            port = 80
        return port

    def command(self, url, command="GET", args=None):
        if (command == "POST"):
            return self.POST( url, args )
        else:
            return self.GET( url, args )
    


if __name__ == "__main__":
    client = HTTPClient()
    command = "GET"
    if (len(sys.argv) <= 1):
        help()
        sys.exit(1)
    elif (len(sys.argv) == 3):
        print(client.command( sys.argv[2], sys.argv[1] ))
    else:
        print(client.command( sys.argv[1] ))
    
    #log.close()



# From my assignment 1; modified 
class HTTPRequest:
    url : urllib.parse.ParseResult
    method : str
    host : str 
    port : int 
    path : str
    headers : dict
    body : str

    def __init__(self, method, url, headers = {}, body = ""):
        self.url = urllib.parse.urlparse(url)
        self.method = method
        if self.url.path == "":
            self.path = "/"
        else:
            self.path = self.url.path
        self.headers = headers
        self.body = body

    def toPayload(self):
        res = f"{self.method} {self.path} HTTP/1.1\r\n"
        for header, value in self.headers.items():
            res += f"{header}: {value}\r\n"
        res += '\r\n'
        res += self.body
        return res
