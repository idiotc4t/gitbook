# 通过伪装PPID提权到SYSTEM

## 简介

代码延用[自启动服务](../persistence/startup-service.md)，由于服务工作在system用户，天生具有很高权限，所以当我们可以控制创建修改进程时，就能轻易的从administrator权限提升到system权限。

## 实现效果

![](../.gitbook/assets/image%20%2812%29.png)

