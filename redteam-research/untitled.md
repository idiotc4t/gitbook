# NtQueryInformationProcess逆向

## 起因

早一段时间有一位朋友问过我如何跨进程获取全路径，当时回答的时候告诉他可以从PEB的LDR链表里和通过QueryFullProcessImageNameW获取，最近闲下来了去逆了一下这个函数，发现并非如此，所以记录一下。

## 过程

首先还是打开文档查一下公开信息，发现这个函数由kernel32导出，把kernel32拖进ida看一下反汇编。

![](../.gitbook/assets/image%20%28254%29.png)

![](../.gitbook/assets/image%20%28249%29.png)

![](../.gitbook/assets/image%20%28255%29.png)

发现实际上这个kernel32导出的这个函数是个转发函数，它由api-ms-win-core-psapi-l1-1-0.dll导出，有经验的朋友可能知道很多api-ms\*系dll在磁盘上根本找不到，找到它拖进ida，发现它只是个字符串。

![](../.gitbook/assets/image%20%28253%29.png)

实际上微软试图将api体系结构和具体的实现分开，但往往一个dll中包含了大量不同体系的实现\(如kernelbase\)，这样微软提出了一种名为\(virtual dlls\)的方案，通过虚拟dll建立一张映射表来转发到实现dll，这样就能把api体系与实现分开。

具体细节可参考[https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html](https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html)

![](../.gitbook/assets/image%20%28247%29.png)

在转发到真实dll kernelbase.dll，同样拖进ida。

![](../.gitbook/assets/image%20%28243%29.png)

在简单逆向之后发现居然是通过NtQueryInformationProcess来实现的，传入的查询参数为flag\*16+27,

根据微前面的参数检测，只有两个可传入值0或1，查看文档。

![](../.gitbook/assets/image%20%28256%29.png)

![](../.gitbook/assets/image%20%28246%29.png)

分别对应了ring0和ring3不同的形式，那么根据逻辑传入的查询参数分别为27或43,我们写一个简单程序验证一下。

```text
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")
int main()
{

    UNICODE_STRING usRing0 = {0};
    UNICODE_STRING usRing3 = { 0 };

    NtQueryInformationProcess(GetCurrentProcess(),(PROCESSINFOCLASS)27,&usRing0, 0x1000, NULL);
    NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)43, &usRing3, 0x1000, NULL);

    getchar();
}

```

![](../.gitbook/assets/image%20%28244%29.png)

## 取巧

当然也有取巧的办法，我们需要请出我们的windbg,查看一下是否记录了这个枚举结构。

```text
0:004> dt *!*Process*Information*Class*
DBGHELP: C:\Users\Black Sheep\source\repos\NtQueryInformationProcess1\x64\Debug\NtQueryInformationProcess1.pdb is a partial PDB and can't enumerate symbol information.
          ole32!PROCESS_INFORMATION_CLASS
          ole32!_PROCESS_INFORMATION_CLASS
          combase!PROCESS_INFORMATION_CLASS
          combase!_PROCESS_INFORMATION_CLASS
0:004> dt ole32!PROCESS_INFORMATION_CLASS
   ProcessMemoryPriority = 0n0
   ProcessMemoryExhaustionInfo = 0n1
   ProcessAppMemoryInfo = 0n2
   ProcessInPrivateInfo = 0n3
   ProcessPowerThrottling = 0n4
   ProcessReservedValue1 = 0n5
   ProcessTelemetryCoverageInfo = 0n6
   ProcessProtectionLevelInfo = 0n7
   ProcessLeapSecondInfo = 0n8
   ProcessInformationClassMax = 0n9
```

很遗憾它没有完全记录这个枚举类型，这时候我想到了ReactOS，尝试去看一下是否在老NT内核就有这个选项，之所以用ReactOS而不是泄露的windows源码是因为ReactOS有维护着的文档，交叉查询起来比较方便。

![](../.gitbook/assets/image%20%28251%29.png)

![](../.gitbook/assets/image%20%28245%29.png)

很幸运，它记录了比较全的枚举结构类型，我们也能比较方便的查看查询返回的结构体，搜索一下引用。

![](../.gitbook/assets/image%20%28248%29.png)

![](../.gitbook/assets/image%20%28252%29.png)

## Links

{% embed url="https://blog.quarkslab.com/runtime-dll-name-resolution-apisetschema-part-i.html" %}



