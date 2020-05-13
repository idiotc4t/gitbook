# 基于dll劫持BypassUac

## dll劫持

> 由于输入表中只包含DLL名而没有它的路径名，因此加载程序必须在磁盘上搜索DLL文件。首先会尝试从当前程序所在的目录加载DLL，如果没找到，则在Windows系统目录中查找，最后是在环境变量中列出的各个目录下查找。利用这个特点，先伪造一个系统同名的DLL，提供同样的输出表，每个输出函数转向真正的系统DLL。程序调用系统DLL时会先调用当前目录下伪造的DLL，完成相关功能后，再跳到系统DLL同名函数里执行。这个过程用个形象的词来描述就是系统DLL被劫持（hijack）了。

参考-&gt;

{% page-ref page="../persistence/dll-hijack.md" %}

## 利用流程

1. 寻找一个带有autoElevate属性又具有dll劫持缺陷的程序
2. 确定可劫持dll
3. 写入恶意dll

## dll劫持bypassuac实验

我们知道在进程创建的时候会复制一份登录用户的主令牌，而令牌内包含的特权又标识着当前进程的权限，部分拥有微软签名又具有autoElevate属性的程序会静默提升权限，本质上是把一个受限的令牌替换成一个高完整性的令牌，同时我们又知道在程序载入dll后在某些情况下程序会自动执行dllmain，如果我们能劫持一个dll，那我们编写的dll也会以拥有高完整性令牌的权限执行。

如何寻找带有autoElevate参考-&gt;

{% page-ref page="bypassuac-fodhelper.md" %}

* 寻找一个带有autoElevate属性又具有dll劫持缺陷的程序

过滤条件:

![](../.gitbook/assets/image%20%2859%29.png)

![](../.gitbook/assets/image%20%2818%29.png)

运行自动提权文件我们发现，在程序当前目录并不存在预期dll，虽然处于system32目录下我们无法直接写入dll，但是操作系统提供的一些功能是可以让我们以受限用户权限越权写入的，如wusa能够将cab文件释放至管理员权限的文件夹，在之后的windows10中虽然取消了该方法，但是同样有等效的替代方案IFileOperation越权复制文件。

在这里笔者就直接把dll放入system32\sysprep\。\(好吧其实是我懒\)。

![](../.gitbook/assets/image%20%2830%29.png)

成功bypassuac，当然如果要武器化,那还需要对dll进行一些优化。

## LINKS

{% embed url="https://github.com/hfiref0x/UACME" %}



