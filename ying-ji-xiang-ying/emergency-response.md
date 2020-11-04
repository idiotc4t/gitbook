# WannaMine4.0专杀的一些技巧

## 简介

今年我们这破地方的卫生系统又双叒叕爆发内网病毒了，这篇文章是记录病毒清理的一个思路，主要是对踩的一些坑的记录，本文仅对木马最后的执行体做查杀，这个病毒是基于WannaCry勒索的变种，仅将最后释放的执行体做了更改。

首先我们需要看一下这个病毒的分析，由于这种病毒已经有师傅做过详尽的分析，这里直接照搬[WPeace](https://bbs.pediy.com/user-home-906228.htm)师傅的流程图。

![&#x6D41;&#x7A0B;&#x56FE;](../.gitbook/assets/image%20%28211%29.png)

## 查杀思路

1. 病毒首先注册污点注册表释放一个随机固定单词组合的一个服务dll，然后注册一个系统服务用svchost.exe带起这个恶意dll，这个注册表键值对里会写入服务名和dll路径和服务的描述信息，这里我们可以直接读取这个键值来获取服务名。

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\NetworkPlatform\Location Awareness
```

![](../.gitbook/assets/image%20%28213%29.png)

![](../.gitbook/assets/image%20%28210%29.png)

![](../.gitbook/assets/image%20%28212%29.png)

```text
	BOOL bRet = EnbalePrivileges(GetCurrentProcess(), SE_DEBUG_NAME);
	if(bRet){
		printf("[+]Enbale DebugPrivileges successful\n");
	}else	{
		printf("[-]Can not Enbale DebugPrivileges successful\n");
	}
	bRet = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\NetworkPlatform\\Location Awareness", 0, KEY_ALL_ACCESS, &hKey);
	if(!bRet){
		printf("[+]Open Key successful\n");
	}else	{
		printf("[-]Can not Open Key successful\n");
	}
	LONG lResult = RegQueryValueExA(hKey,"LastBackup" , NULL, &dwType,
           NULL, &dwSize);
    if (lResult == ERROR_SUCCESS)
       {        
           lResult = RegQueryValueExA(hKey, "LastBackup", NULL, &dwType,
                (LPBYTE)buffer, &dwSize);
            
    }
	if(!lResult){
		printf("[+]Query Key Value successful\n");
	}else	{
		printf("[-]Can not Query Key Value successful\n");
	}
```

2.

