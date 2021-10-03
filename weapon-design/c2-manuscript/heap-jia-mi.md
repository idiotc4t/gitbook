# Heap加密

## 简介

最近堆\(Heap\)加密给BeaconEye整挺火,刚好自己也在写C2,就简单记录下。

## 流程

1. 遍历进程拥有的堆。
2. 编译堆中已分配的块。
3. 异或已分配块中的数据。

## 过程

首先用GetProcessHeaps获取进程拥有的所有堆句柄。

```text
DWORD GetProcessHeaps(
  DWORD   NumberOfHeaps,
  PHANDLE ProcessHeaps
);
```

然后用HeapWalk枚举所有已分配的堆内存块。\(这个函数设计的挺好的终于不用啥First Next了 略略略\)

（heapEntry.wFlags & PROCESS\_HEAP\_ENTRY\_BUSY\)

```text
BOOL HeapWalk(
  HANDLE               hHeap,
  LPPROCESS_HEAP_ENTRY lpEntry
);
```

![](../../.gitbook/assets/image%20%28289%29.png)

![](../../.gitbook/assets/image%20%28288%29.png)

## 代码

```text
#include <windows.h>
#include <stdio.h>


VOID Xor(char* buffer, size_t buffer_size) {
	char key[9] = { 1,2,3,4,5,6,8,0 };

	for (size_t i = 0; i < buffer_size; i++)
	{
		buffer[i] ^= key[i % sizeof(key)-1];
	}
}

VOID FuckHeap() {
	PROCESS_HEAP_ENTRY heapEntry = { 0 };
	HANDLE hHeap = GetProcessHeap();
	while (HeapWalk(hHeap, &heapEntry))
	{
		if (heapEntry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
		{
			Xor((char*)heapEntry.lpData, heapEntry.cbData);
		}
	}
}

int main()
{
	
	LPVOID WorkPath = malloc(MAX_PATH);
	GetCurrentDirectoryA(MAX_PATH, (LPSTR)WorkPath);
	printf("%s\n", (char*)WorkPath);
	FuckHeap();

	//printf("%s\n", (char*)WorkPath);
	FuckHeap();
	printf("%s\n", (char*)WorkPath);

}
```

