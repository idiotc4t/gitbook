# SEH Code Execute

## SEH简介

    SEH\(Structured Exception Handling\)结构化异常处理,是windows操作系统默认的错误处理机制，它允许我们在程序产所错误时使用特定的异常处理函数处理这个异常，尽管提供的功能预取为处理异常，但由于其功能的特点，也往往大量用于反调试。

讲原理的话还挺复杂的，用户层异常涉及到多次换栈cpu层级切换，这里不做简介，有兴趣的可以参考段钢老师的《加密与解密》。

SEH默认存储在栈中，以链表的形式保存其结构如下。

```text
typedef struct _Exception_SEH_List{	
PException_SEH *next;    //*next指针指向下一个节点，	
PException_DISPOSITION handle;    //handle指向一个异常处理函数。
}_Exception_SEH_List,*_Exception_SEH_List;
```

![](../.gitbook/assets/image%20%2890%29.png)

当异常产生时操作系统会接管并会按照\(A\)-&gt;\(B\)-&gt;\(C\)的顺序依次传递，直到异常处理完毕。

异常处理函数通常也遵循约定的编写格式，由于异常处理函数是一个回调函数，所以第一参数是由操作系统传递的一个指向EXCEPTION\_RECORD结构体的指针。

CONTEXT保存CPU处理异常前的状态，用于处理后的恢复。

![](../.gitbook/assets/image%20%2893%29.png)

```text
typedef struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;   //异常代码
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;   //异常发生地址
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD;
```

常见的异常:

```text
EXCEPTION_ACCESS_VIOLATION     0xC0000005     程序企图读写一个不可访问的地址时引发的异常。例如企图读取0地址处的内存。
EXCEPTION_ARRAY_BOUNDS_EXCEEDED    0xC000008C     数组访问越界时引发的异常。
EXCEPTION_BREAKPOINT                           0x80000003     触发断点时引发的异常。
EXCEPTION_DATATYPE_MISALIGNMENT    0x80000002     程序读取一个未经对齐的数据时引发的异常。
EXCEPTION_FLT_DENORMAL_OPERAND     0xC000008D     如果浮点数操作的操作数是非正常的，则引发该异常。所谓非正常，即它的值太小以至于不能用标准格式表示出来。
EXCEPTION_FLT_DIVIDE_BY_ZERO                   0xC000008E     浮点数除法的除数是0时引发该异常。
EXCEPTION_FLT_INEXACT_RESULT           0xC000008F     浮点数操作的结果不能精确表示成小数时引发该异常。
EXCEPTION_FLT_INVALID_OPERATION            0xC0000090     该异常表示不包括在这个表内的其它浮点数异常。
EXCEPTION_FLT_OVERFLOW                             0xC0000091     浮点数的指数超过所能表示的最大值时引发该异常。
EXCEPTION_FLT_STACK_CHECK                  0xC0000092     进行浮点数运算时栈发生溢出或下溢时引发该异常。
EXCEPTION_FLT_UNDERFLOW                    0xC0000093     浮点数的指数小于所能表示的最小值时引发该异常。
EXCEPTION_ILLEGAL_INSTRUCTION          0xC000001D     程序企图执行一个无效的指令时引发该异常。
EXCEPTION_IN_PAGE_ERROR                        0xC0000006     程序要访问的内存页不在物理内存中时引发的异常。
EXCEPTION_INT_DIVIDE_BY_ZERO                   0xC0000094     整数除法的除数是0时引发该异常。
EXCEPTION_INT_OVERFLOW                             0xC0000095     整数操作的结果溢出时引发该异常。
EXCEPTION_INVALID_DISPOSITION                  0xC0000026     异常处理器返回一个无效的处理的时引发该异常。
EXCEPTION_NONCONTINUABLE_EXCEPTION     0xC0000025     发生一个不可继续执行的异常时，如果程序继续执行，则会引发该异常。
EXCEPTION_PRIV_INSTRUCTION                     0xC0000096     程序企图执行一条当前CPU模式不允许的指令时引发该异常。
EXCEPTION_SINGLE_STEP                          0x80000004     标志寄存器的TF位为1时，每执行一条指令就会引发该异常。主要用于单步调试。
EXCEPTION_STACK_OVERFLOW                   0xC00000FD     栈溢出时引发该异常。
```

异常发生的时候，执行异常代码的线程就会发生中断，转而运行SEH，此时操作系统会把线程 CONTEXT结构体的指针传递给异常处理函数的相应参数。由于这个处理函数可以由我们自定义，所以我们可以利用操作系统来帮我执行shellcode，同时由于seh的特殊性，调试器默认会接管异常而不使用seh，所以我们通常会利用seh进行一些反调试。

结构化异常基于线程，每个单独的线程都有自己的seh链，我们可以在TEB.NtTib.ExceptionList找到seh的链表头，而TEB可以在FS:\[00\]寄存器位置找到，NTTIB和ExceptionList分别处于各自结构体第一个成员，所以FS:\[00\]=TEB.NtTib.ExceptionList。

![](../.gitbook/assets/image%20%2892%29.png)

![](../.gitbook/assets/image%20%2891%29.png)

## SEH实现

原始实现：

```text
//1.挂入链表相当于这部分
//fs[0]-> Exception
	_asm
	{
		mov eax, fs:[0]
		mov temp,eax
		lea ecx,Exception
		mov fs:[0],ecx
	}
	//为SEH成员赋值
	Exception.Next = (_EXCEPTION*)temp;
	Exception.Handler = (DWORD)&MyEexception_handler;

//下面是2，3
EXCEPTION_DISPOSITION _cdecl MyEexception_handler
(
	struct _EXCEPTION_RECORD *ExceptionRecord,	//异常结构体
	PVOID EstablisherFrame,						//SEH结构体地址
	struct _CONTEXT *ContextRecord,				//存储异常发生时的各种寄存器的值 栈位置等
	PVOID DispatcherContext
)
{
	if (ExceptionRecord->ExceptionCode == 0xC0000094)		//2.异常过滤
	{
		ContextRecord->Eip = ContextRecord->Eip + 2;			//3.异常处理
		ContextRecord->Ecx = 100;

		return ExceptionContinueExecution;
	}
	return ExceptionContinueSearch;
}
```

编译器封装:

```text
//这里的代码底层实现就类似上面的代码。
_try						//1.挂入链表
	{

	}
	_except(过滤表达式)	//2.异常过滤
	{
		异常处理程序		//3.异常处理程序
	}

异常过滤表达式常量值
1) EXCEPTION_EXECUTE_HANDLER (1)	执行except代码
2) EXCEPTION_CONTINUE_SEARCH (0)	寻找下一个异常处理函数
3) EXCEPTION_CONTINUE_EXECUTION (-1)	返回出错位置重新执行

表达式由多种写法:
1.直接写常量值
_except(EXCEPTION_CONTINUE_EXECUTION)
2.表达式
_except(GetExceptionCode() == 0xC0000094 ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)
3.调用函数
_except(ExceptFilter(GetExceptionInformation()))
```

## SEH利用

如果有调试器并接管异常，那么程序会在发生除零异常的位置停滞，而没有调试器程序则会处理这个异常并执行shellcode。

```text
#include<Windows.h>
#include<stdio.h>
#pragma comment(linker, "/section:.data,RWE")
char shellcode[] =
"";
int a = 1;
int b = 0;

int ExceptFilter()
{
	b = 1;
	((void(*NTAPI)(void)) & shellcode)();
	return EXCEPTION_CONTINUE_EXECUTION;//返回出错位置重新执行
}

int main()
{
	_try
	{
		int c = a / b;
	}
	_except(ExceptFilter()) {
		
	};

	return 0;

}
```

![](../.gitbook/assets/image%20%2895%29.png)

或:

![](../.gitbook/assets/image%20%2894%29.png)

## LINKS

{% embed url="https://www.cnblogs.com/FKdelphi/p/10734361.html" %}

{% embed url="https://bbs.pediy.com/thread-249592.htm" %}

{% embed url="https://blog.csdn.net/weixin\_42052102/article/details/83547922" %}

{% embed url="https://blog.csdn.net/weixin\_42052102/article/details/83551306" %}



