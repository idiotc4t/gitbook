# 载入第二个Ntdll绕Hook

## 简介

我不知道有没有人写过这个东西， 之前和我的亲兄弟[snowming](http://blog.leanote.com/post/snowming/a0366d1d01bf)师傅交流时回想起来用[CreateFileMapping-&gt;MapViewOfFile](../code-and-dll-process-injection/mapping-injection.md)以文件映射的形式打开，如果被打开文件时PE格式，那么这个文件会按照内存展开，那么我们猜想是不是这个被第二次载入内存的ntdll是不是就是一个干净的ntdll，能不能帮助我们绕过一些inline hook。

## 流程

1. 使用CreateFileMapping-&gt;MapViewOfFile映射一个ntdll
2. 自己实现一个GetProcAddress函数
3. 使用自写GetProcAddress函数获取nt函数
4. do it

## 调试

把代码写出来之后windbg调了一下，发现如果没有挂钩，那么这个代码其实和原ntdll是一模一样的，在windbg里面会显示第二个ntdll。\(只是显示成ntdll\_xxx,在ldr链表里还是叫ntdll\)。

![](../.gitbook/assets/image%20%28194%29.png)

![](../.gitbook/assets/image%20%28197%29.png)

如果使用windows api GetProcAddress函数获取函数地址的话会报错0126 找不到指定的模块。\(正在分析原因\)

![](../.gitbook/assets/image%20%28192%29.png)

但是如果我们直接自己编写一个GetProcAddress函数就可以获取到这个自己加载的ntdll内的函数地址并且执行成功。

![](../.gitbook/assets/image%20%28195%29.png)

## 代码

```text
#include <Windows.h>
#include <stdio.h>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect);

FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName)
{
	UINT_PTR uiLibraryAddress = 0;
	FARPROC fpResult = NULL;

	if (hModule == NULL)
		return NULL;
	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS pNtHeaders = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
		pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);
		uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);
		uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);
		uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);
		if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
		{
			uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));
			fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			DWORD dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--)
			{
				char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));
				if (strcmp(cpExportedFunctionName, lpProcName) == 0)
				{
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
					fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));

					break;
				}
				uiNameArray += sizeof(DWORD);
				uiNameOrdinals += sizeof(WORD);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		fpResult = NULL;
	}

	return fpResult;
}


int main() {

	HANDLE hNtdllfile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE hNtdllMapping = CreateFileMapping(hNtdllfile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID lpNtdllmaping = MapViewOfFile(hNtdllMapping, FILE_MAP_READ, 0, 0, 0);

	pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddressR((HMODULE)lpNtdllmaping, "NtAllocateVirtualMemory");

	int err = GetLastError();

	LPVOID Address = NULL;
	SIZE_T uSize = 0x1000;

	NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &Address, 0, &uSize, MEM_COMMIT, PAGE_READWRITE);
	
	

	return 0;
};
```

## LINKS

{% embed url="http://blog.leanote.com/post/snowming/a0366d1d01bf" %}

{% embed url="https://github.com/stephenfewer/ReflectiveDLLInjection" %}



