# 基于断链的DLL隐藏

## 简介

在红队行动的时，我们往往需要往目标系统的某个进程内注入一个自定义的DLL，而这个自定的DLL往往是恶意，如何让这个模块不被蓝队或应急响应工作者更难检测到就是我们需要做的，断链这种技术非常古老，同时应用于非常多的场景，在内核层如果我们需要隐藏一个进程的内核结构体，也会使用这种技术。

## 手工实现

前面写commandline伪装的时候讲到过，操作系统会在ring3维护一个结构体PEB\(进程环境块\)，段寄存器FS:\[00\]\(x86环境\)在三环时始终指向TEB\(线程环境块\)，TEB偏移0x30则指向该进程的PEB。

通常我们可以使用内联汇编的方式获取PEB位于内存的虚拟地址。

```text
mov eax, fs: [0x30] ;　
```

通过windbg定位teb-&gt;peb。

```text
0:007> dt _teb 02f60000
combase!_TEB
   +0x000 NtTib            : _NT_TIB
   +0x01c EnvironmentPointer : (null) 
   +0x020 ClientId         : _CLIENT_ID
   +0x028 ActiveRpcHandle  : (null) 
   +0x02c ThreadLocalStoragePointer : (null) 
   +0x030 ProcessEnvironmentBlock : 0x02f48000 _PEB //PEB的位置
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

在PEB偏移0x0c位置存在着三条模块链表

```text
0:007> dt _peb 0x02f48000
combase!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0x84 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y1
   +0x004 Mutant           : 0xffffffff Void
   +0x008 ImageBaseAddress : 0x001f0000 Void
   +0x00c Ldr              : 0x771e4d80 _PEB_LDR_DATA
   +0x010 ProcessParameters : 0x03042100 _RTL_USER_PROCESS_PARAMETERS
   ···
   +0x464 CloudFileDiagFlags : 0
   +0x468 PlaceholderCompatibilityMode : 2 ''
   +0x469 PlaceholderCompatibilityModeReserved : [7]  ""
   +0x470 LeapSecondData   : 0x7f690000 _LEAP_SECOND_DATA
   +0x474 LeapSecondFlags  : 0
   +0x474 SixtySecondEnabled : 0y0
   +0x474 Reserved         : 0y0000000000000000000000000000000 (0)
   +0x478 NtGlobalFlag2    : 0
```

根据链表含义分别是 加载顺序模块链表、初始化顺序模块链表、内存顺序模块链表。

```
0:007> dt _PEB_LDR_DATA 0x771e4d80
combase!_PEB_LDR_DATA
   +0x000 Length           : 0x30
   +0x004 Initialized      : 0x1 ''
   +0x008 SsHandle         : (null) 
   +0x00c InLoadOrderModuleList : _LIST_ENTRY [ 0x3043e48 - 0x3087fc0 ]
   +0x014 InMemoryOrderModuleList : _LIST_ENTRY [ 0x3043e50 - 0x3087fc8 ]
   +0x01c InInitializationOrderModuleList : _LIST_ENTRY [ 0x3043d70 - 0x3088d90 ]
   +0x024 EntryInProgress  : (null) 
   +0x028 ShutdownInProgress : 0 ''
   +0x02c ShutdownThreadId : (null) 
```

这三条链表实际上是\_LDR\_DATA\_TABLE\_ENTRY结构体的头部。

```text
0:007> dt _LDR_DATA_TABLE_ENTRY  0x703e48
combase!_LDR_DATA_TABLE_ENTRY
   +0x000 InLoadOrderLinks : _LIST_ENTRY [ 0x703d60 - 0x771e4d8c ]
   +0x008 InMemoryOrderLinks : _LIST_ENTRY [ 0x703d68 - 0x771e4d94 ]
   +0x010 InInitializationOrderLinks : _LIST_ENTRY [ 0x0 - 0x0 ]
   +0x018 DllBase          : 0x00c10000 Void
   +0x01c EntryPoint       : 0x00c31860 Void
   +0x020 SizeOfImage      : 0x2e000
   +0x024 FullDllName      : _UNICODE_STRING "C:\WINDOWS\SysWOW64\notepad.exe"
   +0x02c BaseDllName      : _UNICODE_STRING "notepad.exe"
   ···
   +0x064 SwitchBackContext : 0x770c11a4 Void
   +0x068 BaseAddressIndexNode : _RTL_BALANCED_NODE
   +0x074 MappingInfoIndexNode : _RTL_BALANCED_NODE
   +0x080 OriginalBase     : 0xc10000
   +0x088 LoadTime         : _LARGE_INTEGER 0x01d64879`7031a94c
   +0x090 BaseNameHashValue : 0x4c900b25
   +0x094 LoadReason       : 4 ( LoadReasonDynamicLoad )
   +0x098 ImplicitPathOptions : 0
   +0x09c ReferenceCount   : 2
   +0x0a0 DependentLoadFlags : 0
   +0x0a4 SigningLevel     : 0 ''
```

