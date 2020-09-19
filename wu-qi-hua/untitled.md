# COM组件相关的武器化技术

## COM简介

> 由于网上关于直接调用windows内建com组件的编程技术比较稀少\(至少我找了几天没找到\)，该文会简要介绍如何通过已知clsid在自定可执行文件中调用windows com接口，实现部分武器化技术。

{% hint style="danger" %}
文旨在简单介绍调用windows本身com组件的相关编程技术，由于本人非职业开发，理解可能存在一定偏差，如发现有明显错误，请务必直接联系本人\(防止误人子弟略略略略略\)。
{% endhint %}

阅读本文的朋友很大概率经常使用诸如atexec、wmiexec之类的横向移动工具，该类技术其实质也是对dcom\(分布式com\)组件的调用。

com本身是一种开发理念，旨在跨应用和语言共享二进制代码，其理念类似dll，但dll仅能被C/C++理解或遵循C调用规范的语言使用,com通过指明二进制模块必须编译成约定的结构解决了这个问题，其实现方式与c++的类相似，所以通常使用c++来实现一个com组件。

就windows中实现来看，com组件本身仍旧是标准的pe结构\(dll/exe\)，只不过其内部包含了coclass，以及在注册表中注册了相关键值，以便我们找到并使用它。

## 原理

通常windows内建com已经在注册表内存储着相关信息，而自定义com需要创建注册表入口点告诉windows com组件服务器在上面位置，这个过程称之为注册\(Registration\)，我们可以在HKEY\_CLASSES\_ROOT\CLSID\{clsid}位置找到所有windows已注册的com服务器。

![](../.gitbook/assets/image%20%28169%29.png)

注册后com通过GUID\(globally unique identifier\)唯一标识符来寻找并使用这个com组件，理论上每一个GUID\(有时也称UUID\)都是唯一的,GUID在标识不同的对象时会有不同的称呼，标识类对象时称之为CLSID\(类标识符\)、标识接口时被称为IID\(接口标识符\)。



