# 基于内存补丁ETW的绕过

## 简介

通常在红队行动中，面临的最大挑战并不是诸如杀毒、EDR之类的防护软件，红队行动中工具&代码的杀毒绕过只是事前工作\(基本功\)，所以攻击者使用的工具&代码往往在本地就比较完备的完成了免杀工作，在这样的背景下，如何让工具尽可能少的留下痕迹就成为了红队成员首要解决的问题。

在cobaltstrike中实现了在非托管进程中加载托管代码的功能模块execute-assembly，而这个功能因为操作系统提供的API（ ICLRMetaHost[、](https://www.21ct.cc/)ICLRRuntimeInfo、ICLRRuntimeHost）在实现上并不复杂，但是这并不影响它的实用性。

## 技术原理

对于检测CLR进行的操作\(托管进程\)一种比较好的方法就是通过Windows事件跟踪（ETW\),虽然该功能最早是为了调试和监控性能引入的，但是这并不妨碍它成为监控execute-assembly等功能的行为操作。

如我们正常开启一个powershell\(属于托管进程\)，在进程加载过程中就会产生大量日志记录，我们可以通过processhacker，进行查看。

![](../.gitbook/assets/image%20%28118%29.png)

根据前人的研究结果，我们可以知道ETW是由用户空间ntdll.dll!EtwEventWrite发起的\(这里手动@xpn\)，这样我们对其绕过也能比较方便的实现。

> ### How does the CLR surface events via ETW? <a id="how-does-the-clr-surface-events-via-etw"></a>
>
> Hopefully by this point the goal is obvious, we need to stop ETW from reporting our malicious activity to defenders. To do this we first need to understand just how the CLR exposes its events via ETW.
>
> Let's take a look at `clr.dll` to try and see if we can spot the moment that an event is triggered. Loading the PDB and hunting for the `AssemblyDCStart_V1` symbol using Ghidra, we quickly land on the following method:

> ![](../.gitbook/assets/image%20%28116%29.png)
>
>
>
> Let's see if we can find the exact point that an event is generated reporting the Assembly load which we observed above with our ETW consumer. Dropping into WinDBG and setting a breakpoint on all `ntdll!EtwEventWrite` calls occurring after the `ModuleLoad` method above, we quickly discover the following where we can see our Assembly name of "test" is being sent:

> ![](../.gitbook/assets/image%20%28117%29.png)

> So this tells us 2 things. First, these ETW events are sent from userland, and second that these ETW events are issued from within a process that we control... And as we know, having a malicious process report that it is doing something malicious never ends well.

根据XPN大佬的研究结果，我们尝试patch ntdll!EtwEventWrite来验证结论是否正确，这里使用x64dbg和powershell来验证。

首先使用x64dbg创建一个powershell进程，这时x64dbg会在线程初始化前下一个断点。



