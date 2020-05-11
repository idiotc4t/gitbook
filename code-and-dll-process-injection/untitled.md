# NtCreateSection & NtMapViewOfSection Code Execute

## 简介

前面我们介绍过的[mapping injection](mapping-injection.md)技术与当前介绍的没有本质区别，同样是创建一块共享的物理内存，但这个技术更为接近底层，mapping injection使用的api本质上是ntdll导出函数的封装，这个注入技术则是直接调用ntdll的导出函数。

这种技术与mapping injection具有同样的优点，我们可以不使用virutalprotectex、writeprocessmemory等注入技术经典函数。

## 注入流程

1. 在注入进程创建section
2. 将section映射到注入进程虚拟地址\(本进程RW权限\)
3. 往被映射的虚拟地址写入shellcode
4. 打开被注入进程句柄
5. 将section映射到被注入进程虚拟地址\(映射进程RX权限\)
6. 创建远程线程

