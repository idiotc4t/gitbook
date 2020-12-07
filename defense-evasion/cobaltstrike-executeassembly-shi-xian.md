# Execute-Assembly实现

## 简介

cs实现了在非托管程序中加载.net程序集的功能，该功能使我们的恶意.net程序集不落地在内存中执行，这个实质是当前进程通过com接口初始化\(公共语言运行时\)CLR环境，本文尝试对该功能进行复现。

## 流程

1. 初始化ICLRMetaHost接口。
2. 通过ICLRMetaHost获取ICLRRuntimeInfo接口。
3. 通过ICLRRuntimeInfo获取ICLRRuntimeHost接口。
4. 通过ICLRRuntimeHost.Start\(\)初始化CLR。
5. 通过ICLRRuntimeHost.EecuteInDefaultAppDomain执行指定程序集\(硬盘上\)。

