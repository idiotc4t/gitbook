# 获取机器安装的软件

## 简介

通常在获取到入口点之后我们需要快速收集当前主机的凭证，如chrome和navicat内存放的密码，如果能快速取得主机上安装的软件我们就能针对该软件进行密码的提取，本篇文章旨在解决这个问题。

## 原理

也没什么原理，主要是windows在安装软件的时候会注册一些注册表项，这些表项会存放着软件的相关信息。

比如我们熟知的卸载功能：

![](../.gitbook/assets/image%20%28161%29.png)

具体定位到注册表则HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\\*

![](../.gitbook/assets/image%20%28159%29.png)

与之相似的还有WMI class。

注册表则是HKEY\_LOCAL\_MACHINE\SOFTWARE\Classes\Installer\Products\\*

![](../.gitbook/assets/image%20%28160%29.png)

我们可以通过读取注册表子项的键值对来进行快速的确认。

当然这种方式仅对完整安装的软件有效，如果是绿色版的软件则只能通过手工或自动化搜索的方式查找。

