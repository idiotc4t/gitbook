# 攻击demo的bof改造

## 简介

银河系第一C2 cobaltstrike4.1更新了一个神奇的功能，原文直接贴。

> Cobalt Strike has weaponization options for PowerShell, .NET, and Reflective DLLs. These three options rely on Beacon’s [fork&run mechanism](https://youtu.be/Pb6yvcB2aYw?t=620). This is Cobalt Strike’s pattern to spawn a process, inject a capability into it, and receive output over a named pipe. This is OK in some engagements. It’s too OPSEC-expensive in others.
>
> We’ve long had requests for some option to run custom capability directly within the Beacon payload, without fork&run. [Beacon Object Files](https://www.cobaltstrike.com/help-beacon-object-files) are our answer to this request. Beacon Object Files are a way to build small post-ex capabilities that execute in Beacon, parse arguments, call a few Win32 APIs, report output, and exit.
>
> A Beacon Object File is an object file, produced by a C compiler, that is linked and loaded by Cobalt Strike. Beacon Object Files can call Win32 APIs and have access to [some internal Beacon APIs](https://www.cobaltstrike.com/downloads/beacon.h) \(e.g., for output, token impersonation, etc.\).
>
> Here’s an example Beacon Object File \(it’s Beacon’s ‘net domain’ command\)

其他特性我倒是没觉得有什么基本都是些常规技术，主要是小，在dns等传输速率慢的信道内会比较有优势。

## 流程

其实也挺简单的

1. 引入beacon.h头文件
2. 把所有字符串和函数改成ascii的
3. 把所有函数改成beacon.h定义的编写约定
4. 生成bof文件

## 操作&代码

找到一份需要武器化的代码，这里使用[get-computer-installed-software](../persistence/get-computer-installed-software.md)的demo。

```text

#include <stdio.h>
#include <Windows.h>
#include <tchar.h>


BOOL EnumInstalledSoft(TCHAR* subKey, TCHAR* subKeyName) {

	HKEY hKey = NULL;
	HKEY hSubKey = NULL;
	DWORD dwIndexs = 0;
	TCHAR keyName[MAX_PATH] = { 0 };
	DWORD dwLength = 256;
	TCHAR subKeyValue[MAX_PATH] = { 0 };


	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		while (RegEnumKeyEx(hKey, dwIndexs, keyName, &dwLength, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			RegOpenKey(hKey, keyName, &hSubKey);

			RegQueryValueEx(hSubKey,
				subKeyName,
				NULL,
				NULL,
				(LPBYTE)subKeyValue,
				&dwLength);

			printf("%s : %s  \n", keyName, subKeyValue);
			RegCloseKey(hSubKey);
			hSubKey = 0;
			++dwIndexs;
			dwLength = 256;
		}
	}
	else
	{
		return FALSE;
	}
	if (hKey != NULL)
	{
		RegCloseKey(hKey);
		return TRUE;
	}
}

int main()
{


	EnumInstalledSoft((TCHAR*)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",(TCHAR*)"DisplayName");
	EnumInstalledSoft((TCHAR*)"Software\\Classes\\Installer\\Products", (TCHAR*)"ProductName");
	system("pause");


	return 0;
}
```

然后我们导入beacon.h,和替换bof约定的写法，函数原型我们可以使用一个[bof\_helper](https://github.com/dtmsecurity/bof_helper)的项目，这个项目自动化帮我们生成好bof约定的函数原型和写法，如把GetProcAddress换成KERNEL32$GetProcAddress的写法，这里直接使用工具，同时也需要把输出函数换成beacon导出的函数。

![](../.gitbook/assets/image%20%28179%29.png)

还需要把入口点main改名成go最后整个代码看上去是这样的\(比较粗糙没传参\)。

```text

#include <stdio.h>
#include <windows.h>
#include "beacon.h"

DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);

DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyA(HKEY, LPCWSTR, PHKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegEnumKeyExA(
	HKEY,
	DWORD,
	LPWSTR,
	LPDWORD,
	LPDWORD,
	LPWSTR,
	LPDWORD,
	PFILETIME
);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA(
	HKEY,
	LPCWSTR,
	LPDWORD,
	LPDWORD,
	LPBYTE,
	LPDWORD
);

BOOL EnumInstalledSoft(CHAR* subKey, CHAR* subKeyName) {

	HKEY hKey = NULL;
	HKEY hSubKey = NULL;
	DWORD dwIndexs = 0;
	CHAR keyName[MAX_PATH] = { 0 };
	DWORD dwLength = 256;
	CHAR subKeyValue[MAX_PATH] = { 0 };


	if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		while (ADVAPI32$RegEnumKeyExA(hKey, dwIndexs, keyName, &dwLength, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
		{
			ADVAPI32$RegOpenKeyA(hKey, keyName, &hSubKey);

			ADVAPI32$RegQueryValueExA(hSubKey,
				subKeyName,
				NULL,
				NULL,
				(LPBYTE)subKeyValue,
				&dwLength);

			BeaconPrintf(CALLBACK_OUTPUT, "%s : %s  \n", keyName, subKeyValue);
			ADVAPI32$RegCloseKey(hSubKey);
			hSubKey = 0;
			++dwIndexs;
			dwLength = 256;
		}
	}
	else
	{
		return FALSE;
	}
	if (hKey != NULL)
	{
		ADVAPI32$RegCloseKey(hKey);
		return TRUE;
	}
}

int main()
{


	EnumInstalledSoft((CHAR*)"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", (CHAR*)"DisplayName");
	EnumInstalledSoft((CHAR*)"Software\\Classes\\Installer\\Products", (CHAR*)"ProductName");
	return 0;
}
```

效果。

![](../.gitbook/assets/image%20%28180%29.png)

## 缺点

1. 似乎无法使用全局变量
2. 不太适合跑驻留型的任务，跑大量循环会崩溃
3. 一旦引发崩溃整个beacon就会崩掉
4. 不易调试
5. 似乎输出不能使用unicode。

## LINKS

{% embed url="https://blog.cobaltstrike.com/2020/06/25/cobalt-strike-4-1-the-mark-of-injection/" %}

{% embed url="https://github.com/dtmsecurity/bof\_helper" %}



