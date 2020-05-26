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

