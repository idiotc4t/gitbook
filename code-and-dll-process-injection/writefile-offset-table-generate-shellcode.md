# WhiteFile Offset Table Generate Shellcode

## 简介

这篇文章是我还比较菜的时候\(虽然现在也很菜\)，当时看到的时候惊为天人，大概说可以通过计算shellcode需要字符在白文件中的偏移位置，通过记录偏移位置，在不硬编码的情况下还原出shellcode，今天突然想起来，就复现一下。

## 流程

1. 寻找一个全windows都包含且不变的文件\(C:\Windows\Fonts\wingding.ttf\)
2. 遍历文件确认存在全字符\(0x00-0xff\)
3. 计算shellcode在文件内的偏移表
4. 基于便宜表还原shellcode



## 代码

