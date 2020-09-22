# 基于线程关闭的EventLog绕过

## 简介

通常windows系统本身会记录一些较为特殊的操作，如登录、注销，而实现这部分功能通常是由windows自生的服务实现，windows 系统服务主要由svchost.exe进程进行启动和管理，本文会介绍如何从操作系统中识别并结束EventLog的服务线程，然后结束它绕过windows的日志记录。

## 原理



