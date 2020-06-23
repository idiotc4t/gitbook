# 基于断链的DLL隐藏

## 简介

在红队行动的时，我们往往需要往目标系统的某个进程内注入一个自定义的DLL，而这个自定的DLL往往是恶意，如何让这个模块不被蓝队或应急响应工作者更难检测到就是我们需要做的，断链这种技术非常古老，同时应用于非常多的场景，在内核层如果我们需要隐藏一个进程的内核结构体，也会使用这种技术。

在实战场景中，这种技术使用的比较少，如果需要跨进程隐藏的话需要频繁的读内存，或把代码打成shellcode注入目标进程，所以实际使用中往往不如直接使用shellcode来的方便，同时操作系统内核维护了一个vad二叉树，这个二叉树内管理着所有分配的内存和加载的模块,在三环我们往往无法直接操作内核，所以在windbg此类内核调试器中，此类模块隐藏往往没有意义。

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

在PEB偏移0x0c位置存在着三条模块链表。

使用汇编获取。

```text
 mov eax, [eax + 0x0c];
```

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

根据链表含义分别是 模块加载顺序、模块初始化顺序、模块内存顺序。

![](../.gitbook/assets/image%20%28121%29.png)

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

![](../.gitbook/assets/image%20%28122%29.png)

到这里我们的思路应该已经很清晰了，在ring3操作系统维护着模块双向链表，我们只要修改我们想要隐藏的模块的前后两个\_LDR\_DATA\_TABLE\_ENTRY结构体的前后链表就能实现这个效果。

![](../.gitbook/assets/image%20%28126%29.png)

通俗点说，我们只要让 我的下一个模块的前一个模块指向我的前一个，我的前一个模块的下一个模块指向我的下一个。

## 思路

1. 获取PEB地址
2. 获取LDR地址
3. 遍历链表
4. 断链

## 代码实现

```text
#include <stdio.h>
#include <Windows.h>
#include <stdlib.h>


typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG                   Length;
    BOOLEAN                 Initialized;
    PVOID                   SsHandle;
    LIST_ENTRY              InLoadOrderModuleList;
    LIST_ENTRY              InMemoryOrderModuleList;
    LIST_ENTRY              InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY          InLoadOrderModuleList;  
    LIST_ENTRY          InMemoryOrderModuleList;
    LIST_ENTRY          InInitializationOrderModuleList; 
    LPVOID              BaseAddress;  
    LPVOID              EntryPoint;  
    ULONG               SizeOfImage;
    UNICODE_STRING      FullDllName;
    UNICODE_STRING      BaseDllName;
    ULONG               Flags;
    SHORT               LoadCount;
    SHORT               TlsIndex;
    HANDLE              SectionHandle;
    ULONG               CheckSum;
    ULONG               TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;



int main()
{

    HMODULE hMod = GetModuleHandleA("ntdll.dll");
    PPEB_LDR_DATA pLdr;
    PLIST_ENTRY pBack, pNext;
    PLDR_DATA_TABLE_ENTRY pLdm;


    _asm
    {
        mov eax, fs: [0x30] ;　　　　　　　　　
        mov eax, [eax + 0x0c];
        mov pLdr, eax;
    }



    pBack = &(pLdr->InLoadOrderModuleList);         
    pNext = pBack->Flink;              
    do
    {
        pLdm = CONTAINING_RECORD(pNext, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList); 

        if (hMod == pLdm->BaseAddress)                                    
        {                                             
            pLdm->InLoadOrderModuleList.Blink->Flink =                 
                pLdm->InLoadOrderModuleList.Flink;

            pLdm->InLoadOrderModuleList.Flink->Blink =
                pLdm->InLoadOrderModuleList.Blink;

            pLdm->InInitializationOrderModuleList.Blink->Flink =
                pLdm->InInitializationOrderModuleList.Flink;

            pLdm->InInitializationOrderModuleList.Flink->Blink =
                pLdm->InInitializationOrderModuleList.Blink;

            pLdm->InMemoryOrderModuleList.Blink->Flink =
                pLdm->InMemoryOrderModuleList.Flink;

            pLdm->InMemoryOrderModuleList.Flink->Blink =
                pLdm->InMemoryOrderModuleList.Blink;
            break;
        }
        pNext = pNext->Flink;
    } while (pBack != pNext);

    system("pause");
    return 0;
}
```

如果您是究极逻辑怪，还可以看看这个不使用结构体的指针版本。

```text
#include <Windows.h>
#include <stdio.h>

void HideModule(char *szModule)
{
    DWORD *PEB         = NULL,         
        *Ldr         = NULL,        
        *Flink       = NULL,         
        *p           = NULL,         
        *BaseAddress = NULL,         
        *FullDllName = NULL;    
    __asm    
    {        
        mov     eax,fs:[0x30]        
        mov     PEB,eax    
    }    
    
    HMODULE hMod = GetModuleHandle(szModule);

    Ldr   = *( ( DWORD ** )( ( unsigned char * )PEB + 0x0c ) );
    Flink = *( ( DWORD ** )( ( unsigned char * )Ldr + 0x0c ) ); 
    p     = Flink;    

    do    
    {        
        BaseAddress = *( ( DWORD ** )( ( unsigned char * )p + 0x18 ) );        
        FullDllName = *( ( DWORD ** )( ( unsigned char * )p + 0x28 ) );
        if (BaseAddress == (DWORD *)hMod)
        {
            **( ( DWORD ** )(p + 1) ) = (DWORD)*( ( DWORD ** )p );
            *(*( ( DWORD ** )p ) + 1) = (DWORD)*( ( DWORD ** )(p + 1) );
            break;
        }
        p = *( ( DWORD ** )p );    
    }    while ( Flink != p ); 
    
    Flink = *( ( DWORD ** )( ( unsigned char * )Ldr + 0x14 ) ); 
    p     = Flink;    
    do    
    {    
        BaseAddress = *( ( DWORD ** )( ( unsigned char * )p + 0x10 ) );        
        FullDllName = *( ( DWORD ** )( ( unsigned char * )p + 0x20 ) );        
        if (BaseAddress == (DWORD *)hMod)
        {
            **( ( DWORD ** )(p + 1) ) = (DWORD)*( ( DWORD ** )p );
            *(*( ( DWORD ** )p ) + 1) = (DWORD)*( ( DWORD ** )(p + 1) );
            break;
        }
        p = *( ( DWORD ** )p );    
    }    while ( Flink != p ); 
    
    Flink = *( ( DWORD ** )( ( unsigned char * )Ldr + 0x1c ) );
    p     = Flink;    
    do    
    {        
        BaseAddress = *( ( DWORD ** )( ( unsigned char * )p + 0x8 ) );        
        FullDllName = *( ( DWORD ** )( ( unsigned char * )p + 0x18 ) );        
        if (BaseAddress == (DWORD *)hMod)
        {
            **( ( DWORD ** )(p + 1) ) = (DWORD)*( ( DWORD ** )p );
            *(*( ( DWORD ** )p ) + 1) = (DWORD)*( ( DWORD ** )(p + 1) );
            break;
        }
        p = *( ( DWORD ** )p );    
    }    while ( Flink != p ); 
}

int main(int argc, char* argv[])
{
    HideModule("kernel32.dll");

    getchar();

	return 0;
}
```

![](../.gitbook/assets/image%20%28115%29.png)

## LINKS

{% embed url="https://www.epubit.com/bookDetails?id=N40707" %}

{% embed url="https://bbs.pediy.com/thread-225832.htm" %}

{% embed url="https://www.cnblogs.com/iBinary/p/9601860.html" %}



