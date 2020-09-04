# 获取机器安装的软件

## 简介

通常在获取到入口点之后我们需要快速收集当前主机的凭证，如chrome和navicat内存放的密码，如果能快速取得主机上安装的软件我们就能针对该软件进行密码的提取，本篇文章旨在解决这个问题。

## 原理

也没什么原理，主要是windows在安装软件的时候会注册一些注册表项，这些表项会存放着软件的相关信息。

比如我们熟知的卸载功能：

![](../.gitbook/assets/image%20%28163%29.png)

具体定位到注册表则HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\\*

![](../.gitbook/assets/image%20%28159%29.png)

与之相似的还有WMI class。

注册表则是HKEY\_LOCAL\_MACHINE\SOFTWARE\Classes\Installer\Products\\*

![](../.gitbook/assets/image%20%28160%29.png)

我们可以通过读取注册表子项的键值对来进行快速的确认，投入实战的话需要对系统进行判断，如果是x64位系统则需要对32位程序也进行遍历。（x64系统存在注册表重定位）

![](../.gitbook/assets/image%20%28161%29.png)

当然这种方式仅对完整安装的软件有效，如果是绿色版的软件则只能通过手工或自动化搜索的方式查找。

## 代码

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

![](../.gitbook/assets/image%20%28162%29.png)

## LINKS

{% embed url="https://docs.microsoft.com/zh-cn/?view=vs-2019" %}



