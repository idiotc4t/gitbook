# 通过com组件BypassUAC

## COM组件简介

> COM component（COM组件）是微软公司为了计算机工业的软件生产更加符合人类的行为方式开发的一种新的软件开发技术。在COM构架下，人们可以开发出各种各样的功能专一的组件，然后将它们按照需要组合起来，构成复杂的应用系统。

com组件本质上是二进制文件\(dll、exe,在windows系统内\),其调用方法与c++的类相似，程序可以通过被称为CLSID\(全局标识符\)作为索引在注册表内找到具体的二进制文件，这篇文章只会介绍应用方法，具体的逆向分析会在之后的文章内详细解释\(等公司买正版ida,现在用的盗版就不拿出来丢人了\)。

windows提供了一种com组件提权的方法，其原意大概是为了方便开发，所以当这种提提权方法的调用者是拥有微软签名的合法程序时，会忽略uac弹窗，这也为了我们利用该技术埋下了隐患。

在com组件中，有一个名为ICMLuaUtil的接口，这个接口提供了一个名为ShellExec的方法，顾名思义，可以执行任意传入的命令，如果我们能用提权的ICMLuaUtil接口调用ShellExec，那么我们就能获得一个不受限的管理员令牌。

## 流程

1. 初始化com库
2. 创建提升权限的ICMLuaUtil接口
3. 调用ICMLuaUtil的ShellExec方法
4. 弹出一个高权限的calc\(串戏了\)。
