# 动态获取系统调用\(syscall\)号

## 简介

众所周知不同的系统版本，进入内核的系统调用号不尽相同，之前对手工重写函数的时候免不了硬编码调用号，这使得我们写出来的木马兼容性不是特别好，需要对不同的系统进行定制化处理。

对系统调用不太了解的旁友请移步[通过重写ring3 API函数实现免杀](overwrite-winapi-bypassav.md)。

这种技术是看到这篇[漏洞利用缓解part2](https://www.crowdstrike.com/blog/state-of-exploit-development-part-2/)的启发，在windows 1607版本后，PTE也进行了随机化基址处理。

![](../.gitbook/assets/image%20%28168%29.png)

但有某位神仙安全研究员在blackhat公开了通过nt!MiGetPteAddress函数中获取实例化的PTE\(可能形容不是很恰当\)，通过这种思路，我联想到同样可以应用于syscall，于是就有了这篇文章，不同于上述技术syscall id直接硬编码于ntdll.dll。

## 思路

1. 通过GetProcAddress获取ntdll内的函数。
2. 读取函数偏移0x04获取系统调用号
3. 编辑函数模板填入调用号
4. 编写函数指针对函数模板进行调用

![](../.gitbook/assets/image%20%28165%29.png)

## 代码

不同于页表,ntdll也可以直接解析PE格式来获取调用号，由于我本人比较懒，这里只给出内存动态读取的demo。

![](../.gitbook/assets/image%20%28166%29.png)

实现效果。

![](../.gitbook/assets/image%20%28164%29.png)

```text
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#pragma comment(linker, "/section:.data,RWE")//.data段可执行

CHAR FuncExample[] = {
	0x4c,0x8b,0xd1,			  //mov r10,rcx
	0xb8,0xb9,0x00,0x00,0x00, //mov eax,0B9h
	0x0f,0x05,				  //syscall
	0xc3					  //ret
};

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(//函数指针
	HANDLE ProcessHandle,
	PVOID* BaseAddress, 
	ULONG_PTR ZeroBits, 
	PSIZE_T RegionSize, 
	ULONG AllocationType, 
	ULONG Protect);


DOUBLE GetAndSetSysCall(TCHAR* szFuncName) {
	DWORD SysCallid = 0;
	HMODULE hModule = GetModuleHandle(_T("ntdll.dll"));
	DWORD64 FuncAddr = (DWORD64)GetProcAddress(hModule, (LPCSTR)szFuncName);
	LPVOID CallAddr = (LPVOID)(FuncAddr + 4);
	ReadProcessMemory(GetCurrentProcess(), CallAddr, &SysCallid, 4, NULL);
	memcpy(FuncExample+4, (CHAR*)&SysCallid, 2);
	return (DOUBLE)SysCallid;
}

int main() {
	LPVOID Address = NULL;
	SIZE_T uSize = 0x1000;
	DOUBLE call = GetAndSetSysCall((TCHAR*)"NtAllocateVirtualMemory");
	pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)&FuncExample;
	NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &Address, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	return 0;

}
```

## LINKS

{% embed url="https://www.crowdstrike.com/blog/state-of-exploit-development-part-2/" %}

{% embed url="https://j00ru.vexillium.org/syscalls/nt/64/" %}



