# 载入第二个Ntdll绕Hook

## 简介

我不知道有没有人写过这个东西， 之前和我的亲兄弟[snowming](http://blog.leanote.com/post/snowming/a0366d1d01bf)师傅交流时回想起来用[CreateFileMapping-&gt;MapViewOfFile](../code-and-dll-process-injection/mapping-injection.md)以文件映射的形式打开，如果被打开文件时PE格式，那么这个文件会按照内存展开，那么我们猜想是不是这个被第二次载入内存的ntdll是不是就是一个干净的ntdll，能不能帮助我们绕过一些inline hook。

## 流程

1. 使用CreateFileMapping-&gt;MapViewOfFile映射一个ntdll
2. 自己实现一个GetProcAddress函数
3. 使用自写GetProcAddress函数获取nt函数
4. do it

## 调试

把代码写出来之后windbg调了一下，发现如果没有挂钩，那么这个代码其实和原ntdll是一模一样的，在windbg里面会显示第二个ntdll。

![](../.gitbook/assets/image%20%28192%29.png)

![](../.gitbook/assets/image%20%28193%29.png)



