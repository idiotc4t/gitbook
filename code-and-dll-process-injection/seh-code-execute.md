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

