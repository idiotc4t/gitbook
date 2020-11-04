# WannaMine4.0专杀的一些技巧

## 简介

今年我们这破地方的卫生系统又双叒叕爆发内网病毒了，这篇文章是记录病毒清理的一个思路，主要是对踩的一些坑的记录，本文仅对木马最后的执行体做查杀，这个病毒是基于WannaCry勒索的变种，仅将最后释放的执行体做了更改。

首先我们需要看一下这个病毒的分析，由于这种病毒已经有师傅做过详尽的分析，这里直接照搬[WPeace](https://bbs.pediy.com/user-home-906228.htm)师傅的流程图。

![&#x6D41;&#x7A0B;&#x56FE;](../.gitbook/assets/image%20%28211%29.png)

## 查杀思路

病毒首先注册污点注册表释放一个随机固定单词组合的一个服务dll，然后注册一个系统服务用svchost.exe带起这个恶意dll，这个注册表键值对里会写入服务名和dll路径和服务的描述信息，这里我们可以直接读取这个键值来获取服务名。

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\NetworkPlatform\Location Awareness
```

![](../.gitbook/assets/image%20%28214%29.png)

![](../.gitbook/assets/image%20%28210%29.png)

![](../.gitbook/assets/image%20%28213%29.png)

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

根据多次调试，已经跑沙箱，发现这个病毒的流程并不固定，它可能会带起各种各样的进程，如果我们不结束这些进程就无法用常规的方法删除他们，当然也可以干掉启动项，然后重启删除他们，但这样会对业务产生影响，这里使用了结束进程树的方式，结束进程树可以干掉所有由父进程带起来的子进程以及子进程的子进程。

![](../.gitbook/assets/image%20%28215%29.png)

![](../.gitbook/assets/image%20%28212%29.png)

只要我们结束了最上级进程，那它下属的所有进程都会被结束\(结束进程树\)，这样我们就有两种思路：

1. 定位其中一个进程查找可结束的最上级进程\(这里是服务，所有windows服务都是由services进程带起的，所以查找到父进程是services.exe就代表这个进程是可结束的最上级进程\)。
2. 通过服务名定位服务进程实例\(由于这个病毒是用服务带起来的所以，本文采用这种方法\)。

现在我们就通过windows的services api定位，代码如下:

```text
void KillProcessTree(DWORD dwProcessId) {

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnap, &pe)) {
        do {
            if (pe.th32ParentProcessID == dwProcessId)
                KillProcessTree(pe.th32ProcessID);
        } while (Process32Next(hSnap, &pe));
    }


    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (hProc) {
        TerminateProcess(hProc, 1);
        CloseHandle(hProc);
    }
}
	
	bRet = QueryServiceStatusEx(
        hService,           
        SC_STATUS_PROCESS_INFO,   
        (LPBYTE)&ssStatus,           
        sizeof(SERVICE_STATUS_PROCESS),
        &outSize);

	if(bRet){
		printf("[+]Query ServiceStatus successful\n");
	}else	{
		printf("[-]Can not Query ServiceStatus successful\n");
	}
	if(ssStatus.dwProcessId!=0){
		KillProcessTree(ssStatus.dwProcessId);
	}

	bRet = DeleteService(hService);
```

