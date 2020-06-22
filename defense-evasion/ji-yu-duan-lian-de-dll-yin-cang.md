# 基于断链的DLL隐藏

## 简介

在红队行动的时，我们往往需要往目标系统的某个进程内注入一个自定义的DLL，而这个自定的DLL往往是恶意，如何让这个模块不被蓝队或应急响应工作者更难检测到就是我们需要做的，断链这种技术非常古老，同时应用于非常多的场景，在内核层如果我们需要隐藏一个进程的内核结构体，也会使用这种技术。

## 手工实现

前面写commandline伪装的时候讲到过，操作系统会在ring3维护一个结构体PEB\(进程环境块\)，段寄存器FS:\[00\]\(x86环境\)在三环时始终指向TEB\(线程环境块\)，TEB偏移0x30则指向该进程的PEB。

```text
0:007> dt _teb 02f60000
combase!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : (null) 
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : (null) 
   +0x02c ThreadLocalStoragePointer : (null) 
   +0x030 ProcessEnvironmentBlock : 0x02f48000 _PEB
   +0x034 LastErrorValue   : 0
   +0x038 CountOfOwnedCriticalSections : 0
   +0x03c CsrClientThread  : (null) 
   +0x040 Win32ThreadInfo  : (null) 
   +0x044 User32Reserved   : [26] 0
   ···
   +0xfd8 LockCount        : 0
   +0xfdc WowTebOffset     : 0n-8192
   +0xfe0 ResourceRetValue : (null) 
   +0xfe4 ReservedForWdf   : (null) 
   +0xfe8 ReservedForCrt   : 0
   +0xff0 EffectiveContainerId : _GUID {00000000-0000-0000-0000-000000000000}
```

通常我们可以使用内联汇编的方式获取PEB位于内存的虚拟地址。

```text
mov eax, fs: [0x30] ;　
```



