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

