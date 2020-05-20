# TLS Code Execute

## TLS简介

> 线程局部存储（Thread Local Storage，TLS）用来将数据与一个正在执行的指定线程关联起来。
>
> 进程中的全局变量与函数内定义的静态\(static\)变量，是各个线程都可以访问的共享变量。在一个线程修改的内存内容，对所有线程都生效。这是一个优点也是一个缺点。说它是优点，线程的数据交换变得非常快捷。说它是缺点，一个线程死掉了，其它线程也性命不保; 多个线程访问共享数据，需要昂贵的同步开销，也容易造成同步相关的BUG。
>
> 如果需要在一个线程内部的各个函数调用都能访问、但其它线程不能访问的变量（被称为static memory local to a thread 线程局部静态变量），这就是TLS。

TLS提供了一个回调函数\(callback function\)，在线程程初始化和终止的时候都会调用，由于回调函数会在入口点\(EP\)前执行，而调试器通常会默认在主函数入口点main设置断点，所以常常被用来作为反调试手段使用，同时回调函数允许我们自由编写任意代码，TLS分为静态TLS和动态TLS，静态TLS会把TLS相关数据硬编码在PE文件内，在本篇文章内我们使用静态TLS来实现代码执行。

## 静态TLS

TLS回调函数遵循特殊的编写约定，与dll主函数相似。

```text
typedef VOID
(NTAPI *PIMAGE_TLS_CALLBACK) (
 PVOID DllHandle, 
 DWORD Reason, //Reason 遵循dll调用时相同的参数
 PVOID Reserved
 );
```

静态TLS存储在PE头IMAGE\_DATA\_DIRECTORY DataDirectory\[9\]的位置，同其他目录表数组一样，也是8字节结构 \(VA+Size\)，从TLS的VA处，可以找到该目录的详细信息。

```text
typedef struct _IMAGE_TLS_DIRECTORY32 {   //SIZE:0x18h
    DWORD   StartAddressOfRawData;
    DWORD   EndAddressOfRawData;
    DWORD   AddressOfIndex;             // PDWORD
    DWORD   AddressOfCallBacks;         // PIMAGE_TLS_CALLBACK *
    DWORD   SizeOfZeroFill;
    DWORD   Characteristics;
} IMAGE_TLS_DIRECTORY32;
typedef IMAGE_TLS_DIRECTORY32 * PIMAGE_TLS_DIRECTORY32;
```

## 代码实现

```text
#include <Windows.h>
#include <stdio.h>
#pragma comment(linker, "/section:.data,RWE") 

unsigned char buf[] ="shellcode";


VOID NTAPI TlsCallBack(PVOID DllHandle, DWORD dwReason, PVOID Reserved) 
//DllHandle模块句柄、Reason调用原因、 Reserved加载方式（显式/隐式）
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		((void(WINAPI*)(void)) & buf)();
	}

}
//使用TLS需要在程序中新建一个.tls段专门存放TLS数据，申明使用
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")



#pragma data_seg (".CRT$XLB")
//.CRT表明是使用C RunTime机制，$后面的XLB中：X表示随机的标识
//L表示是TLS callback section，B可以被换成B到Y之间的任意一个字母，
//但是不能使用“.CRT$XLA”和“.CRT$XLZ”，因为“.CRT$XLA”和“.CRT$XLZ”是用于tlssup.obj的。
EXTERN_C PIMAGE_TLS_CALLBACK _tls_callback = TlsCallBack;
#pragma data_seg ()

int main()
{
	printf("ok");
	return 0;
}
```

