# 自启动服务

通常windows服务运行在session 0，隔断了系统服务和桌面系统，各个session之间相互独立，不能交互和通信。

系统进程自启动是通过windows系统提供的api创建系统服务，并设置服务为自启动类型实现的，创建系统服务的时候要求具有管理员权限，作为系统服务启动的程序需要存在一个额外的服务入口点ServiceMain，通常需要把不需要用户交互的操作放在这里面，如果需要与用户交互，可以通过WTS系列函数来实现。

## 创建流程

1. 获取SCManager句柄
2. 通过SCManager对服务进行增删查改

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

