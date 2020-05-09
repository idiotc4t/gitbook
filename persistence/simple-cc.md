# 编写简单远控

## 简介

通常在使用cmd控制台中执行命令，本质上是执行windows目录下的system32&syswow64内的可执行文件，通常此类操作可以通过winexec，system等函数进行模拟cmd下命令的执行，但是此类命令往往没有回显，这对我们查看命令执行结果造成一些麻烦。

好在windows提供了一种在进程间共享数据的机制，我们称其为管道\(pipe\)，在windows中其实质是一段共享内存，windows为这段内存设计使用数据流I/O的方式来进行访问。

管道具体又分为匿名管道和命名管道，匿名管道只能用于父子进程之间的数据通信，不能在网络中通信，同时数据传输时单项的，只能一端读，一端写。命名管道则可以在任意进程和网络间通信，且数据是双向的，但同一时间只能一端读一端写。

在windows操作系统提供的createprocess函数可以可以指定程序运行结果存储的缓冲区，如果我们把这个缓冲区指定成匿名管道的写入端，那么我们就能在父进程内进行对执行结果的读取。

## 流程

1. 创建匿名管道
2. 创建STARTUPINFO结构体
3. 创建进程
4. 等待执行结束
5. 读取缓冲区

## 代码实现

```text
#include<Windows.h>
#include<stdio.h>

int main() {

	SECURITY_ATTRIBUTES se = { 0 };
	se.bInheritHandle = TRUE;//描述的对象可以被继承
	se.nLength = sizeof(se);
	se.lpSecurityDescriptor = NULL;


	HANDLE hWPipe=NULL;
	HANDLE hRPipe=NULL;

	CreatePipe(&hRPipe, &hWPipe, &se, NULL);


	STARTUPINFOA si = { 0 };
	si.cb = sizeof(si);
	si.hStdError = hWPipe;
	si.hStdOutput = hWPipe;
	si.wShowWindow = SW_HIDE;//隐藏窗口

	si.dwFlags = STARTF_USESHOWWINDOW //启用wShowWindow成员
			   | STARTF_USESTDHANDLES;//启用hStdOutput，hStdError和hStdInput成员

	PROCESS_INFORMATION pi = { 0 };

	CreateProcessA(NULL, (LPSTR)"systeminfo", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
	
	WaitForSingleObject(pi.hProcess, INFINITE);
	WaitForSingleObject(pi.hThread,INFINITE);

	LPVOID lpBuffer[4096] = { 0 };

	ReadFile(hRPipe, lpBuffer, 4096, NULL, NULL);


	printf("%s", lpBuffer);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hWPipe);
	CloseHandle(hRPipe);

	return 0;

}
```

![](../.gitbook/assets/image%20%2866%29.png)

## LINKS

{% embed url="https://docs.microsoft.com/zh-cn/?view=vs-2019" %}



