# Table of contents

* [关于这个博客](README.md)

## 武器化 <a id="weaponization"></a>

* [COM组件相关的武器化开发技术](weaponization/com-weaponization.md)
* [攻击demo的bof改造](weaponization/bof-weaponization.md)

## 权限提升 <a id="privilege-escalation"></a>

* [基于注册表劫持BypassUAC](privilege-escalation/bypassuac-fodhelper.md)
* [基于dll劫持BypassUac](privilege-escalation/dll-hijack-bypassuac.md)
* [通过com组件BypassUAC](privilege-escalation/com-bypassuac.md)
* [通过复制Token提权到SYSTEM](privilege-escalation/token-manipulation.md)
* [通过code&dll注入提权到SYSTEM](privilege-escalation/code-dll-injection-privilege-escalation.md)
* [通过伪装PPID提权到SYSTEM](privilege-escalation/privilege-escalation-ppid.md)
* [通过系统服务提权到SYSTEM](privilege-escalation/privilege-escalation-service.md)

## 防御逃避 <a id="defense-evasion"></a>

* [编译时混淆字符串&函数调用](defense-evasion/compile-time-obfuscation.md)
* [基于线程结束的EventLog绕过](defense-evasion/fuck-eventlog.md)
* [动态获取系统调用\(syscall\)号](defense-evasion/dynamic-get-syscallid.md)
* [基于内存补丁的AMSI绕过](defense-evasion/memory-pacth-bypass-amsi.md)
* [基于API Hook和DLL注入的AMSI绕过](defense-evasion/apihook-and-dllinjection-bypass-amsi.md)
* [基于内存补丁ETW的绕过](defense-evasion/memory-pacth-bypass-etw.md)
* [基于断链的DLL隐藏](defense-evasion/unlink-module-hide.md)
* [基于HEX字符串执行的AV绕过](defense-evasion/hex-execute.md)
* [CobaltStrike Argue命令实现](defense-evasion/cobaltstrike-argue.md)
* [简单的分离免杀](defense-evasion/simple-separate-bypassav.md)
* [伪装PPID规避检测](defense-evasion/fake-ppid.md)
* [伪装命令行规避检测](defense-evasion/fake-commandline.md)
* [通过重写ring3 API函数实现免杀](defense-evasion/overwrite-winapi-bypassav.md)
* [动态调用无导入表编译](defense-evasion/avtive-call-api.md)
* [基于Registry的虚拟机检测](defense-evasion/rregistry-check-virtualmachine.md)
* [利用杀毒软件删除任意文件](defense-evasion/using-antivirus-to-delete-files.md)
* [反转字符串绕杀软](defense-evasion/reverse-strings-bypass-av.md)
* [重新加载.text节拖钩](defense-evasion/zhong-xin-jia-zai-.text-jie-tuo-gou.md)

## 代码与进程注入 <a id="code-and-dll-process-injection"></a>

* [APC Thread Hijack](code-and-dll-process-injection/apc-thread-hijack.md)
* [CreateRemoteThread](code-and-dll-process-injection/createremotethread.md)
* [APC Injection](code-and-dll-process-injection/apc-injection.md)
* [Mapping Injection](code-and-dll-process-injection/mapping-injection.md)
* [Bypass Session 0 Injection](code-and-dll-process-injection/bypass-session-0-injection.md)
* [WhiteFile Offset Table Generate Shellcode](code-and-dll-process-injection/writefile-offset-table-generate-shellcode.md)
* [Early Bird](code-and-dll-process-injection/early-bird.md)
* [Early Bird & CreateRemoteThread](code-and-dll-process-injection/early-bird-and--createremotethread.md)
* [TLS Code Execute](code-and-dll-process-injection/tls-code-execute.md)
* [SEH Code Execute](code-and-dll-process-injection/seh-code-execute.md)
* [APC & NtTestAlert Code Execute](code-and-dll-process-injection/apc-and-nttestalert-code-execute.md)
* [NtCreateSection & NtMapViewOfSection Code Execute](code-and-dll-process-injection/untitled.md)
* [Process Hollowing](code-and-dll-process-injection/process-hollowing.md)
* [SetContext Hijack Thread](code-and-dll-process-injection/setcontext-hijack-thread.md)
* [DLL Hollowing](code-and-dll-process-injection/dll-hollowing.md)

## 权限维持 <a id="persistence"></a>

* [寻找有价值的文件](persistence/find-file.md)
* [获取机器安装的软件](persistence/get-computer-installed-software.md)
* [通过API添加Windows用户](persistence/api-add-user.md)
* [Detours InLine Hook](persistence/detous-inline-hook.md)
* [DLL劫持](persistence/dll-hijack.md)
* [RID劫持](persistence/rid-hijack.md)
* [自启动服务](persistence/startup-service.md)
* [编写简单远控](persistence/simple-cc.md)
* [注册表自启动项](persistence/registry-startup.md)

