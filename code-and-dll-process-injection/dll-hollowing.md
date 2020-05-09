# DLL Hollowing

## 简介

模块镂空\(dll hollowing\)也是一种shellcode注入技术，原理和思路与process hollowing类似，通过合法的模块信息来伪装恶意代码，虽然我们可以用远程dll注入来完整注入整个恶意dll，但此类注入往往比较容易检测，我们需要往受害者主机上传入一个恶意dll，这样杀毒软件可以通过监控入windows/temp/等目录实现对远程dll注入的拦截，而模块镂空就不会存在这样的风险，因为我们镂空的往往是一个带有微软签名的dll，为了防止进程出错，我们并不能直接镂空一个进程空间中已存在的dll，需要先对目标进程远程注入一个系统合法dll，然后再镂空它，这样我们就获得了一个和windows模块相关联的shellcode环境。

## 实现思路

1. 远程注入一个系统dll\(原理参考[CreateRemoteThrea](createremotethread.md)的dll注入\)

