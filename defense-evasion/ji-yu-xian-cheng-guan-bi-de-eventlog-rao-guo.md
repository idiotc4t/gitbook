# 基于线程关闭的EventLog绕过

## 简介

通常windows系统本身会记录一些较为特殊的操作，如登录、注销，而实现这部分功能通常是由windows自生的服务实现，windows 系统服务主要由svchost.exe进程进行启动和管理，本文会介绍如何从操作系统中识别并结束EventLog的服务线程，然后结束它绕过windows的日志记录。

## 流程

1. 找到EventLog对应的进程
2. 找到EventLog进程具体的服务线程
3. 结束服务线程

## 原理

首先我们需要定位到EventLog服务对应的进程，使用windows的services.msc查看发现windows服务是由svchost指定-s参数查询注册服务进行启动，那我们可以通过遍历系统所有进程的commandline是否带有eventlog服务名来进行识别，主要实现方式由两种，通过进程快照遍历或通过调用wmi接口来识别。

```text
Get-WmiObject -Class win32_service -Filter "name = 'eventlog'" | select -exp ProcessId
```

![](../.gitbook/assets/image%20%28182%29.png)

![&#x90E8;&#x5206;&#x53C2;&#x6570;&#x88AB;&#x906E;&#x6321;](../.gitbook/assets/image%20%28183%29.png)

获取到进程号之后我们需要识别具体的服务线程，在windows vista之后的系统，具体的服务线程约定使用servicemain作为入口点，同时服务线程自身会带有一个等同于服务名的tag，这个tag可以帮我们识别这个线程是否是我们寻找的，在x64线程teb中0x1720偏移的位置存放着service tag的句柄，我们可以那这个句柄使用I\_QueryTagInformation api查询到具体service tag内容。\(句柄-&gt;内容，需要查询内核\_eprocess句柄表，有机会补上\)。

![](../.gitbook/assets/image%20%28181%29.png)

