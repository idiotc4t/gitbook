# 基于内存补丁ETW的绕过

## 简介

通常在红队行动中，面临的最大挑战并不是诸如杀毒、EDR之类的防护软件，红队行动中工具&代码的杀毒绕过只是事前工作\(基本功\)，所以攻击者使用的工具&代码往往在本地就比较完备的完成了免杀工作，在这样的背景下，如何让工具尽可能少的留下痕迹就成为了红队成员首要解决的问题。

在cobaltstrike中实现了在非托管进程中加载托管代码的功能模块execute-assembly，而这个功能因为操作系统提供的API（ ICLRMetaHost[、](https://www.21ct.cc/)ICLRRuntimeInfo、ICLRRuntimeHost）在实现上并不复杂，但是这并不影响它的实用性。

## 技术原理

对于检测CLR进行的操作\(托管进程\)一种比较好的方法就是通过Windows事件跟踪（ETW\),虽然该功能最早是为了调试和监控性能引入的，但是这并不妨碍它成为监控execute-assembly等功能的行为操作。

如我们正常开启一个powershell\(属于托管进程\)，在进程加载过程中就会产生大量日志记录，我们可以通过processhacker，进行查看。

![](../.gitbook/assets/image%20%28125%29.png)

根据前人的研究结果，我们可以知道ETW是由用户空间ntdll.dll!EtwEventWrite发起的\(这里手动@xpn\)，这样我们对其绕过也能比较方便的实现。

> ### How does the CLR surface events via ETW? <a id="how-does-the-clr-surface-events-via-etw"></a>
>
> Hopefully by this point the goal is obvious, we need to stop ETW from reporting our malicious activity to defenders. To do this we first need to understand just how the CLR exposes its events via ETW.
>
> Let's take a look at `clr.dll` to try and see if we can spot the moment that an event is triggered. Loading the PDB and hunting for the `AssemblyDCStart_V1` symbol using Ghidra, we quickly land on the following method:

> ![](../.gitbook/assets/image%20%28116%29.png)

> Let's see if we can find the exact point that an event is generated reporting the Assembly load which we observed above with our ETW consumer. Dropping into WinDBG and setting a breakpoint on all `ntdll!EtwEventWrite` calls occurring after the `ModuleLoad` method above, we quickly discover the following where we can see our Assembly name of "test" is being sent:

> ![](../.gitbook/assets/image%20%28124%29.png)

> So this tells us 2 things. First, these ETW events are sent from userland, and second that these ETW events are issued from within a process that we control... And as we know, having a malicious process report that it is doing something malicious never ends well.

根据XPN大佬的研究结果，我们尝试patch ntdll!EtwEventWrite来验证结论是否正确，这里使用x64dbg和powershell来验证。

首先使用x64dbg创建一个powershell进程，这时x64dbg会在线程初始化前下一个断点。

定位到ntdll!EtwEventWrite。

![](../.gitbook/assets/image%20%28118%29.png)

一般windows api默认使用stdcall\(x86\)调用约定，这里x64默认使用fastcall，即寄存器传参，被调用者清理堆栈，所以我们直接返回就好，以防万一我们确认一下，堆栈的平衡方式会决定我们的内存补丁写法\(这里之前看错了，把后面那个add rsp,58以为是函数内那个call的\)。

![](../.gitbook/assets/image%20%28123%29.png)

这时我们使用一起BypassAmsi的方式在函数开头直接返回。

![](../.gitbook/assets/image%20%28119%29.png)

在processhacker中查看clr日志。

![](../.gitbook/assets/image%20%28120%29.png)

我们发现现在无法读取到任何日志。

## 代码

代码的话拿AMSI的随便改改就行。

由于ntdll在进程加载之初就已经导入，所以这里不需要短暂睡眠，直接挂起创建就行。

```text

#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
int main() {
	STARTUPINFOA si = {0};
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);

	CreateProcessA(NULL, (LPSTR)"powershell -NoExit", NULL, NULL, NULL, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	LPVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");

	//Sleep(500);

	DWORD oldProtect;
	char patch = 0xc3;

	VirtualProtectEx(pi.hProcess, (LPVOID)pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(pi.hProcess, (LPVOID)pEtwEventWrite, &patch, sizeof(char),NULL);

	VirtualProtectEx(pi.hProcess, (LPVOID)pEtwEventWrite, 1, oldProtect, NULL); 
	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	//FreeLibrary(hNtdll);
	return 0;

}
```

![](../.gitbook/assets/image%20%28117%29.png)

## LINKS

{% embed url="https://blog.xpnsec.com/hiding-your-dotnet-etw/" %}



