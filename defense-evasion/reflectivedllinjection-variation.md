# ReflectiveDLLInjection变形应用

## 简介

反射注入\(ReflectiveInjection\)这种技术也出来好多年了，实现原理大致是不依赖windows提供的loadlibrary函数，程序设计者自己在程序内实现pe的内存展开，由于是自己实现，所以不会在操作系统中有所记录，以及可以对展开的pe文件做一些处理如抹除DOS头，同时不会在peb的ldr链表中记录，发展至今反射注入几乎已经是所有c2的标配技术，github也有非常成熟的项目可供使用，不过由于使用量较大，建议还是简单修改一下再投入实战比较好。

下面写的东西和上面的描述有关系\(dog头\)，可能有的渗透测试工作者不熟悉反射加载的原理，但你一定用过它，较为知名的msf和cs也大量使用这种技术，说是c2的基础技术也不为过，这篇文章会介绍两个应用方式，以及一些优化的思路，以供我们更好的吊打蓝队。

## DLL自加载

在cs的资源文件中所有dll都带有自加载能力，所有beacon的扩展功能几乎都是这样实现的\(如mimikatz\)，cs将其称之为可修补的dll，它的原理是在不改变MZ标志的情况下把整个dll文件修补成可被当作shellcode加载的格式，具体的操作为在dll内导出自加载函数\(ReflectiveLoader\)然后讲MZ头起始字节修改成执行ReflectiveLoader函数的硬编码。

### 流程

1. 将ReflectiveLoader库编译进DLL内。
2. 不破坏MZ标志将DOS头改造成执行ReflectiveLoader函数的shellcode。

### 原理

首先我们不能破坏PE结构也就是DOS头内的MZ标志，如果我们要把dll处理成shellcode，那么MZ标志就要被当作是代码执行。

我们将MZ的机器码转换成汇编指令，这里以X86为例，文章末尾也会给出X64的代码。

![](../.gitbook/assets/image%20%28225%29.png)

可以看到MZ对应的汇编代码是↓，我们需要消除这两条指令的影响。

```text
dec ebp                  ;ebp -1
pop edx                  ;edx=[esp] esp+4
//恢复环境
inc ebp                  ;ebp +1
push edx                 ;esp-4 [esp]=edx
```

然后需要将执行指针\(eip/rip\)指向ReflectiveLoader。

```text
call 0                   ;获取下一条指令的内存地址
pop edx                  ;将下一条指令出栈给edx
add edx,<FuncOffset-0x09>;计算ReflectiveLoader函数在内存中的位置
push ebp
mov ebp, esp             ;切换堆栈
call edx                 ;调用ReflectiveLoader
```

修补过后↓，这里代码使用[https://github.com/rapid7/ReflectiveDLLInjection](https://github.com/rapid7/ReflectiveDLLInjection)。

![](../.gitbook/assets/image%20%28227%29.png)

![](../.gitbook/assets/image%20%28224%29.png)

### 优化

我们看到反射加载的DLL在内存中还是会存在很明显的PE格式文件特征，接下来我们尝试把他的PE特征抹掉。\(涉及项目，代码就不贴了\)。

优化前。

![](../.gitbook/assets/image%20%28231%29.png)

优化后。

![](../.gitbook/assets/image%20%28230%29.png)

聪明的你应该已经想到我做了什么\(狗头\)。

## PE-&gt;SHELLCODE改造

上面的操作大概是这样的↓，学过shellcode开发的朋友可能知道，如果我们直接在DLL文件内编写加载函数是不能使用一些编写语法的如字符串、函数、CRT之类的东西的，就算要用系统函数也不能直接调用，前面我们使用的[ReflectiveDLLInjection](https://github.com/rapid7/ReflectiveDLLInjection)项目

![](../.gitbook/assets/image%20%28232%29.png)



### LINKS

{% embed url="https://wbglil.github.io/2020/03/27/%E5%85%B3%E4%BA%8E%E5%8F%8D%E5%B0%84dll%E4%BF%AE%E8%A1%A5/" %}

{% embed url="https://github.com/rapid7/ReflectiveDLLInjection" %}


