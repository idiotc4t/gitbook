# 攻击demo的bof改造

## 简介

银河系第一C2 cobaltstrike4.1更新了一个神奇的功能，原文直接贴。

> Cobalt Strike has weaponization options for PowerShell, .NET, and Reflective DLLs. These three options rely on Beacon’s [fork&run mechanism](https://youtu.be/Pb6yvcB2aYw?t=620). This is Cobalt Strike’s pattern to spawn a process, inject a capability into it, and receive output over a named pipe. This is OK in some engagements. It’s too OPSEC-expensive in others.
>
> We’ve long had requests for some option to run custom capability directly within the Beacon payload, without fork&run. [Beacon Object Files](https://www.cobaltstrike.com/help-beacon-object-files) are our answer to this request. Beacon Object Files are a way to build small post-ex capabilities that execute in Beacon, parse arguments, call a few Win32 APIs, report output, and exit.
>
> A Beacon Object File is an object file, produced by a C compiler, that is linked and loaded by Cobalt Strike. Beacon Object Files can call Win32 APIs and have access to [some internal Beacon APIs](https://www.cobaltstrike.com/downloads/beacon.h) \(e.g., for output, token impersonation, etc.\).
>
> Here’s an example Beacon Object File \(it’s Beacon’s ‘net domain’ command\)

其他特性我倒是没觉得有什么基本都是些常规技术，主要是小，在dns等传输速率慢的信道内会比较有优势。

## 流程

其实也挺简单的

1. 引入beacon.h头文件
2. 把所有字符串和函数改成ascii的
3. 把所有函数改成beacon.h定义的编写约定
4. 生成bof文件

## 操作&代码

1. 找到一份需要武器化的代码，这里使用[get-computer-installed-software](../persistence/get-computer-installed-software.md)的demo。

