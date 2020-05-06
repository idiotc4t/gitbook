# 注册表自启动项

## 简介

为了便于使用，操作系统通常会提供开机自启动功能，这样能方便用户不用人为的去运行程序就能自己运行起来，由于开机自启动的特殊性，此类功能也往往是红蓝对抗重点博弈的地方。

本文将介绍如通过注册表项实现病毒木马自启动。

## 流程

1. 打开自启动键
2. 写入自启动键

由于windows提供了专门的开机启动注册表项，每次开机操作系统都会遍历这个注册表项下的键值对，获取并创建进程，所以我们只需要添加这个注册表项就能实现自启动。

这里给出两个表项，他们的最主要的区别就是主键写入权限的不同。

PS：32位程序往64位注册表内写入数据时会发生重定位。

```text
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

## 代码实现

由于通过cmd添加键值的方式已被众所周知，这里只给出c实现的代码。

```text


#include <Windows.h>
#include <stdio.h>

BOOL SetKeyValue(PCHAR lpszFileName, PCHAR lpszKeyValue,CHAR cType) {
	HKEY hKey=NULL;
	PCHAR KeyAddr=NULL;
	switch (cType)
	{
	case 1:
		KeyAddr = (PCHAR)"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run";
		break;
	case 2:
		KeyAddr = (PCHAR)"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
		break;
	case 3:
		break;

	}

	if (ERROR_SUCCESS!=RegOpenKeyEx(HKEY_CURRENT_USER,KeyAddr,0,KEY_WRITE,&hKey))
	{
		return FALSE;
	}
	if (ERROR_SUCCESS!= RegSetValueEx(hKey,lpszKeyValue,0,REG_SZ,(PBYTE)lpszFileName,1+strlen(lpszFileName)))
	{
		RegCloseKey(hKey);
		return FALSE;
	}
	RegCloseKey(hKey);
}

int  main()
{	
	if (FALSE == SetKeyValue((PCHAR)"C:\\Windows\\System32\\cmd.exe", (PCHAR)"cmd",1))
	{
		printf("ok");
	}
	return 0;
}

```

## LINKS

{% embed url="https://docs.microsoft.com/zh-cn/?view=vs-2019" %}

