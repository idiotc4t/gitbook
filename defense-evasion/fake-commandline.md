# 伪装命令行规避检测

## 简介

在蓝队排查恶意进程过程中，经常会使用processexplorer等进程检查工具进行详细的检测，而通常的恶意进程往往特征会比较明显，这种技术通过伪造PEB进程环境块来伪装自己，让自己的特征不那么明显，从而增加一点存活率。

## 手工操作

在windbg中我们可以比较方便的获取当前附加进程的PEB,由于PEB存储在用户空间，所以不需要进行内核级的操作我们就能对其修改，在ring3用户层x86系统下PEB通常存储在fs:\[30\]的位置，而x64系统则有细微差异，存储在gs:\[0x60\]的位置，在x86系统中我们通常使用内联汇编的方式获取peb的地址，而在x64中这种方式在编写上不那么方便，所以使用另一种利用操作系统函数NtQueryInformationProcess函数获取。

查看当前进程PEB。

```text
0:001> dt _peb @$peb
ntdll!_PEB
   +0x000 InheritedAddressSpace : 0 ''
   +0x001 ReadImageFileExecOptions : 0 ''
   +0x002 BeingDebugged    : 0x1 ''
   +0x003 BitField         : 0x4 ''
   +0x003 ImageUsesLargePages : 0y0
   +0x003 IsProtectedProcess : 0y0
   +0x003 IsImageDynamicallyRelocated : 0y1
   +0x003 SkipPatchingUser32Forwarders : 0y0
   +0x003 IsPackagedProcess : 0y0
   +0x003 IsAppContainer   : 0y0
   +0x003 IsProtectedProcessLight : 0y0
   +0x003 IsLongPathAwareProcess : 0y0
   +0x004 Padding0         : [4]  ""
   +0x008 Mutant           : 0xffffffff`ffffffff Void
   +0x010 ImageBaseAddress : 0x00007ff6`90600000 Void
   +0x018 Ldr              : 0x00007ffc`46fa53c0 _PEB_LDR_DATA
   +0x020 ProcessParameters : 0x00000240`e4b220e0 _RTL_USER_PROCESS_PARAMETERS
   +0x028 SubSystemData    : (null) 
   +0x030 ProcessHeap      : 0x00000240`e4b20000 Void
   +0x038 FastPebLock      : 0x00007ffc`46fa4fe0 _RTL_CRITICAL_SECTION
   +0x040 AtlThunkSListPtr : (null) 
   +0x048 IFEOKey          : (null) 
   +0x050 CrossProcessFlags : 0
   +0x050 ProcessInJob     : 0y0
   +0x050 ProcessInitializing : 0y0
   +0x050 ProcessUsingVEH  : 0y0
   +0x050 ProcessUsingVCH  : 0y0
   +0x050 ProcessUsingFTH  : 0y0
   +0x050 ProcessPreviouslyThrottled : 0y0
   +0x050 ProcessCurrentlyThrottled : 0y0
   +0x050 ProcessImagesHotPatched : 0y0
   +0x050 ReservedBits0    : 0y000000000000000000000000 (0)
   +0x054 Padding1         : [4]  ""
   +0x058 KernelCallbackTable : (null) 
   +0x058 UserSharedInfoPtr : (null) 
   +0x060 SystemReserved   : 0
   +0x064 AtlThunkSListPtr32 : 0
   +0x068 ApiSetMap        : 0x00000240`e49a0000 Void
   +0x070 TlsExpansionCounter : 0
   +0x074 Padding2         : [4]  ""
   +0x078 TlsBitmap        : 0x00007ffc`46fa5340 Void
   +0x080 TlsBitmapBits    : [2] 0x10011
   +0x088 ReadOnlySharedMemoryBase : 0x00007df4`bc970000 Void
   +0x090 SharedData       : (null) 
   +0x098 ReadOnlyStaticServerData : 0x00007df4`bc970750  -> (null) 
   +0x0a0 AnsiCodePageData : 0x00007df5`beab0000 Void
   +0x0a8 OemCodePageData  : 0x00007df5`beab0000 Void
   +0x0b0 UnicodeCaseTableData : 0x00007df5`beae0028 Void
   +0x0b8 NumberOfProcessors : 0xc
   +0x0bc NtGlobalFlag     : 0
   +0x0c0 CriticalSectionTimeout : _LARGE_INTEGER 0xffffe86d`079b8000
   +0x0c8 HeapSegmentReserve : 0x100000
   +0x0d0 HeapSegmentCommit : 0x2000
   +0x0d8 HeapDeCommitTotalFreeThreshold : 0x10000
   +0x0e0 HeapDeCommitFreeBlockThreshold : 0x1000
   +0x0e8 NumberOfHeaps    : 3
   +0x0ec MaximumNumberOfHeaps : 0x10
   +0x0f0 ProcessHeaps     : 0x00007ffc`46fa3c40  -> 0x00000240`e4b20000 Void
   +0x0f8 GdiSharedHandleTable : (null) 
   +0x100 ProcessStarterHelper : (null) 
   +0x108 GdiDCAttributeList : 0
   +0x10c Padding3         : [4]  ""
   +0x110 LoaderLock       : 0x00007ffc`46f9f4f8 _RTL_CRITICAL_SECTION
   +0x118 OSMajorVersion   : 0xa
   +0x11c OSMinorVersion   : 0
   +0x120 OSBuildNumber    : 0x47bb
   +0x122 OSCSDVersion     : 0
   +0x124 OSPlatformId     : 2
   +0x128 ImageSubsystem   : 3
   +0x12c ImageSubsystemMajorVersion : 0xa
   +0x130 ImageSubsystemMinorVersion : 0
   +0x134 Padding4         : [4]  ""
   +0x138 ActiveProcessAffinityMask : 0xfff
   +0x140 GdiHandleBuffer  : [60] 0
   +0x230 PostProcessInitRoutine : (null) 
   +0x238 TlsExpansionBitmap : 0x00007ffc`46fa5320 Void
   +0x240 TlsExpansionBitmapBits : [32] 1
   +0x2c0 SessionId        : 3
   +0x2c4 Padding5         : [4]  ""
   +0x2c8 AppCompatFlags   : _ULARGE_INTEGER 0x0
   +0x2d0 AppCompatFlagsUser : _ULARGE_INTEGER 0x0
   +0x2d8 pShimData        : 0x00000240`e49e0000 Void
   +0x2e0 AppCompatInfo    : (null) 
   +0x2e8 CSDVersion       : _UNICODE_STRING ""
   +0x2f8 ActivationContextData : 0x00000240`e49d0000 _ACTIVATION_CONTEXT_DATA
   +0x300 ProcessAssemblyStorageMap : (null) 
   +0x308 SystemDefaultActivationContextData : 0x00000240`e49c0000 _ACTIVATION_CONTEXT_DATA
   +0x310 SystemAssemblyStorageMap : (null) 
   +0x318 MinimumStackCommit : 0
   +0x320 SparePointers    : [4] (null) 
   +0x340 SpareUlongs      : [5] 0
   +0x358 WerRegistrationData : (null) 
   +0x360 WerShipAssertPtr : (null) 
   +0x368 pUnused          : (null) 
   +0x370 pImageHeaderHash : (null) 
   +0x378 TracingFlags     : 0
   +0x378 HeapTracingEnabled : 0y0
   +0x378 CritSecTracingEnabled : 0y0
   +0x378 LibLoaderTracingEnabled : 0y0
   +0x378 SpareTracingBits : 0y00000000000000000000000000000 (0)
   +0x37c Padding6         : [4]  ""
   +0x380 CsrServerReadOnlySharedMemoryBase : 0x00007df4`28530000
   +0x388 TppWorkerpListLock : 0
   +0x390 TppWorkerpList   : _LIST_ENTRY [ 0x0000009c`16855390 - 0x0000009c`16855390 ]
   +0x3a0 WaitOnAddressHashTable : [128] (null) 
   +0x7a0 TelemetryCoverageHeader : (null) 
   +0x7a8 CloudFileFlags   : 0xe0
   +0x7ac CloudFileDiagFlags : 0
   +0x7b0 PlaceholderCompatibilityMode : 2 ''
   +0x7b1 PlaceholderCompatibilityModeReserved : [7]  ""
   +0x7b8 LeapSecondData   : 0x00007df5`beaa0000 _LEAP_SECOND_DATA
   +0x7c0 LeapSecondFlags  : 0
   +0x7c0 SixtySecondEnabled : 0y0
   +0x7c0 Reserved         : 0y0000000000000000000000000000000 (0)
   +0x7c4 NtGlobalFlag2    : 0
```

通过前人的逆向分析，我们知道在ProcessExplorer等工具会从PEB+0x20的位置的\_RTL\_USER\_PROCESS\_PARAMETERS结构体内读取path，commandline等相关数据。



![](../.gitbook/assets/image%20%2828%29.png)

```text
ntdll!_RTL_USER_PROCESS_PARAMETERS
   +0x000 MaximumLength    : 0x718
   +0x004 Length           : 0x718
   +0x008 Flags            : 0x6001
   +0x00c DebugFlags       : 0
   +0x010 ConsoleHandle    : 0x00000000`00000050 Void
   +0x018 ConsoleFlags     : 0
   +0x020 StandardInput    : 0x00000000`00000054 Void
   +0x028 StandardOutput   : 0x00000000`00000058 Void
   +0x030 StandardError    : 0x00000000`0000005c Void
   +0x038 CurrentDirectory : _CURDIR
   +0x050 DllPath          : _UNICODE_STRING ""
   +0x060 ImagePathName    : _UNICODE_STRING "C:\Windows\system32\cmd.exe"
   +0x070 CommandLine      : _UNICODE_STRING ""C:\Windows\system32\cmd.exe" "
   +0x080 Environment      : 0x00000240`e4b36440 Void
   +0x088 StartingX        : 0
   +0x08c StartingY        : 0
   +0x090 CountX           : 0
   +0x094 CountY           : 0
   +0x098 CountCharsX      : 0
   +0x09c CountCharsY      : 0
   +0x0a0 FillAttribute    : 0
   +0x0a4 WindowFlags      : 1
   +0x0a8 ShowWindowFlags  : 1
   +0x0b0 WindowTitle      : _UNICODE_STRING "C:\Windows\system32\cmd.exe"
   +0x0c0 DesktopInfo      : _UNICODE_STRING "Winsta0\Default"
   +0x0d0 ShellInfo        : _UNICODE_STRING ""
   +0x0e0 RuntimeData      : _UNICODE_STRING ""
   +0x0f0 CurrentDirectores : [32] _RTL_DRIVE_LETTER_CURDIR
   +0x3f0 EnvironmentSize  : 0x1136
   +0x3f8 EnvironmentVersion : 7
   +0x400 PackageDependencyData : (null) 
   +0x408 ProcessGroupId   : 0x41f0
   +0x40c LoaderThreads    : 0
   +0x410 RedirectionDllName : _UNICODE_STRING ""
   +0x420 HeapPartitionName : _UNICODE_STRING ""
   +0x430 DefaultThreadpoolCpuSetMasks : (null) 
   +0x438 DefaultThreadpoolCpuSetMaskCount : 0

```

可以看到在\_RTL\_USER\_PROCESS\_PARAMETERS+0x60和+0x70的位置存储这我们感兴趣的两个—UNICODE\_STRING结构体，通过查看这两个结构体我们可以知道其指向的字符串存放位置。

```text
0:001> dt _UNICODE_STRING 0x00000240`e4b220e0+0x60
ntdll!_UNICODE_STRING
 "C:\Windows\system32\cmd.exe"
   +0x000 Length           : 0x36
   +0x002 MaximumLength    : 0x38
   +0x008 Buffer           : 0x00000240`e4b22728  "C:\Windows\system32\cmd.exe"
0:001> dt _UNICODE_STRING 0x00000240`e4b220e0+0x70
ntdll!_UNICODE_STRING
 ""C:\Windows\system32\cmd.exe" "
   +0x000 Length           : 0x3c
   +0x002 MaximumLength    : 0x3e
   +0x008 Buffer           : 0x00000240`e4b22760  ""C:\Windows\system32\cmd.exe" "
```

将其指向的字符串进行修改，需要注意的是修改字符串的同时最好也要修改该结构体的Lenght的成员，可以看到在修改指针指向内容后，显示会按照我们预期的方式进行。

```text
0:001> eu 0x00000240`e4b22728 "C:\\Windows\\System32\\notepad.exe"
0:001> eu 0x00000240`e4b22760 "C:\\Windows\\System32\\pad.exe"
0:001> dt _UNICODE_STRING 0x00000240`e4b220e0+0x60
ntdll!_UNICODE_STRING
 "C:\Windows\System32\notepad"
   +0x000 Length           : 0x36
   +0x002 MaximumLength    : 0x38
   +0x008 Buffer           : 0x00000240`e4b22728  "C:\Windows\System32\notepad"
0:001> dt _UNICODE_STRING 0x00000240`e4b220e0+0x70
ntdll!_UNICODE_STRING
 "C:\Windows\System32\pad.exee" "
   +0x000 Length           : 0x3c
   +0x002 MaximumLength    : 0x3e
   +0x008 Buffer           : 0x00000240`e4b22760  "C:\Windows\System32\pad.exee" "

```

![](../.gitbook/assets/image%20%2854%29.png)

## 代码实现

由于修改指向内存内容的方式比较沙雕，给出的代码会使用修改指针的方式实现。

```text
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>


typedef DWORD(*pNtQueryInformationProcess) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int main()
{
	HANDLE hProcess =0;
	ULONG lenght = 0;
	HANDLE hModule;
	PROCESS_BASIC_INFORMATION ProcessInformation;
	pNtQueryInformationProcess NtQueryInformationProcess;
	wchar_t CommandLine[] = L"C:\\Windows\\system32\\notepad.exe";
	wchar_t CurrentDirectory[] = L"C:\\Windows\\system32\\";

	hModule =  GetModuleHandleA("Ntdll.dll");
	hProcess = GetCurrentProcess();
	NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	NtQueryInformationProcess(hProcess, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &lenght);

	//WriteProcessMemory(hProcess, ProcessInformation.PebBaseAddress->ProcessParameters->CommandLine.Length, &CommandLine, sizeof(CommandLine), NULL);
	//WriteProcessMemory(hProcess, ProcessInformation.PebBaseAddress->ProcessParameters->ImagePathName.Length, &CurrentDirectory, sizeof(CurrentDirectory), NULL);
	ProcessInformation.PebBaseAddress->ProcessParameters->CommandLine.Length = sizeof(CommandLine);
	ProcessInformation.PebBaseAddress->ProcessParameters->ImagePathName.Length = sizeof(CurrentDirectory);
	ProcessInformation.PebBaseAddress->ProcessParameters->CommandLine.Buffer = &CommandLine;
	ProcessInformation.PebBaseAddress->ProcessParameters->ImagePathName.Buffer = &CurrentDirectory;

	getchar();
	return 0;
}
```

![](../.gitbook/assets/image%20%2875%29.png)

## LINKS

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess" %}



