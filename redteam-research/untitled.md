# NtQueryInformationProcess逆向

## 起因

早一段时间有一位朋友问过我如何跨进程获取全路径，当时回答的时候告诉他可以从PEB的LDR链表里和通过QueryFullProcessImageNameW获取，最近闲下来了去逆了一下这个函数，发现并非如此，所以记录一下。

