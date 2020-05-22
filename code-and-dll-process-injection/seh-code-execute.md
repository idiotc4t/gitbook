# SEH Code Execute

## SEH简介

    SEH\(Structured Exception Handling\)结构化异常处理,是windows操作系统默认的错误处理机制，它允许我们在程序产所错误时使用特定的异常处理函数处理这个异常，尽管提供的功能预取为处理异常，但由于其功能的特点，也往往大量用于反调试。

SEH默认存储与堆栈中，以链表的形式保存其结构如下。

```text
typedef struct _Exception_SEH_List{	
PException_SEH *next;    //*next指针指向下一个节点，	
PException_DISPOSITION handle;    //handle指向一个异常处理函数。
}_Exception_SEH_List,*_Exception_SEH_List;
```

![](../.gitbook/assets/image%20%2890%29.png)

当异常产生时会按照\(A\)-&gt;\(B\)-&gt;\(C\)的顺序依次传递，直到异常处理完毕。

异常处理函数通常也遵循约定的编写格式。

![](../.gitbook/assets/image%20%2891%29.png)

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

