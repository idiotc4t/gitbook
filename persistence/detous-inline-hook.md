# Detours InLine Hook

## Inline hook 简介

通常hook是指一种改变代码执行流程将其拦截并重定向到另一片代码块的技术，其实现方式有很多种，针对ring3\(用户层\)，常见的有虚表vitualtables hook，inline hook，iat hook，callbackhook等，本文介绍的inline hook使用修改函数具体代码实现的执行链劫持，在windows 10操作系统中由于ASLR\(地址随机化\)的缘故，手工实现InLine比较麻烦，这里使用微软的一个轻量级的开源库。

详见该开源库的wiki。

![](../.gitbook/assets/image%20%28102%29.png)

![](../.gitbook/assets/image%20%28100%29.png)

## 示例代码

```text
#include<Windows.h>
#include<stdio.h>
#include "include/detours.h"
#if _X64
#pragma comment(lib,"lib.X64/detours.lib")
#else
#pragma comment(lib,"lib.X86/detours.lib")
#endif

static int (WINAPI* OldMesssageBoxA)
(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
    ) = MessageBoxA;

int WINAPI MyFunction0(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    return OldMesssageBoxA(NULL, "Hooking your MessageBoxA!", "Warming", MB_OKCANCEL);
}

int main() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OldMesssageBoxA, MyFunction0);
    //DetourDetach(&(PVOID&)OldMesssageBoxA, MyFunction0);
    DetourTransactionCommit();

    MessageBoxA(0, 0, 0, 0);


	return 0;
}
```

![](../.gitbook/assets/image%20%28101%29.png)

## RdpThief应用

前段时间\(很久很久以前\)，有一篇专门讲通过detours窃取rdp凭证的文章，这里作为案例复现一下。

起一个rdp客户端创建连接。

![](../.gitbook/assets/image%20%28104%29.png)

搜索用户名。

![](../.gitbook/assets/image%20%28103%29.png)

![](../.gitbook/assets/image%20%28105%29.png)

密码也是同样，这里密码通过不能通过字符串搜索直接出结果，但根据查看函数调用可知具体密码处于CryptProtectMemory函数第一个参数所指向的内存区域偏移+4的位置。

![](../.gitbook/assets/image%20%28107%29.png)

具体ip地址也是一样。

![](../.gitbook/assets/image%20%28106%29.png)

github:[https://github.com/0x09AL/RdpThief.git](https://github.com/0x09AL/RdpThief.git)

## LINKS

{% embed url="https://www.cnblogs.com/M-Anonymous/p/9766343.html" %}

{% embed url="https://github.com/microsoft/Detours/wiki/OverviewInterception" %}

{% embed url="https://blog.csdn.net/systemino/article/details/103083541" %}



