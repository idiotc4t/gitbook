# 寻找有价值的文件

## 简介

我也不知道这玩意大概有什么价值，只是说一般成熟的集成攻击框架内基本都有这样的功能，能从操作系统中搜索带有特定关键字或后缀的文件，这些文件能很大程度帮助我们更好的完成红队任务，虽然此类功能一般也不会被杀软拦掉\(略略略\)。\(可别拿去写勒索病毒！\)。

## 流程

1. 通过路径创建一个搜索句柄
2. 遍历这个搜索句柄

## 代码

这玩意就比较简单了，和之前遍历进程的功能非常相似，同样也是用到了操作系统提供的api。

```text
HANDLE FindFirstFileA(
  LPCSTR             lpFileName,
  LPWIN32_FIND_DATAA lpFindFileData
);

BOOL FindNextFileA(
  HANDLE             hFindFile,
  LPWIN32_FIND_DATAA lpFindFileData
);
```

需要注意的是搜索句柄需要用FindClose函数来关闭。

如果需要更细粒度的文件遍历可以使用FindFirstFileEx去创建搜索句柄。

```text
#include <Windows.h>
#include <stdio.h>
#include <string.h>

void SearchFile(char* pszDirectory,char* pszSuffix)
{
	DWORD dwBufferSize = 2048;
	char FileName[MAX_PATH] = {0};
	char TempPath[MAX_PATH] = {0};
	WIN32_FIND_DATA fdFileData = { 0 };


	wsprintf(FileName, "%s\\*.*", pszDirectory);

	HANDLE hFile = FindFirstFileA(FileName, &fdFileData);

	if (INVALID_HANDLE_VALUE != hFile)
	{
		do
		{
			if ('.' == fdFileData.cFileName[0])
			{
				continue;
			}
			wsprintf(TempPath, "%s\\%s", pszDirectory, fdFileData.cFileName);
			if (fdFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
			{
				SearchFile(TempPath, pszSuffix);
			}
			else
			{
				if (strstr(TempPath, pszSuffix))
				{
					printf("%s\n", TempPath);
				}
			}

		} while (FindNextFileA(hFile, &fdFileData));
	}

	FindClose(hFile);
}

int main(int argc, char* argv[])
{
	SearchFile((char*)"C:\\Users\\Black Sheep\\Desktop",(char*)".exe");

	return 0;
}
```

![](../.gitbook/assets/image%20%28135%29.png)

## LINKS

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilea" %}



