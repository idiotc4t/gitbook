# Execute-Assembly实现

## 简介

cs实现了在非托管程序中加载.net程序集的功能，该功能使我们的恶意.net程序集不落地在内存中执行，这个实质是当前进程通过com接口初始化\(公共语言运行时\)CLR环境，本文尝试对该功能进行复现。

> ### ICLRMetaHost 接口 
>
> 提供一些方法，这些方法基于公共语言运行时的版本号返回特定版本的公共语言运行时 \(\) ，列出所有已安装的 Clr，列出在指定进程中加载的所有运行时，发现编译程序集所用的 CLR 版本，退出使用干净运行时关闭的进程，以及查询旧的 API 绑定。
>
> GetRuntime 方法  
> 获取与特定 CLR 版本相对应的 ICLRRuntimeInfo 接口。 此方法取代了与STARTUP\_LOADER\_SAFEMODE标志一起使用的CorBindToRuntimeEx函数。
>
> ### ICLRRuntimeInfo 接口
>
> 接口 提供一些方法，这些方法可返回有关特定公共语言运行时 \(CLR\) 的信息，包括版本、目录和加载状态。 此接口还提供了特定于运行时的功能，而无需初始化运行时。 它包括运行时相对 LoadLibrary 方法、运行时模块特定的 GetProcAddress 方法和通过 GetInterface 方法提供的运行时提供的接口。
>
> GetInterface 方法  
> 将 CLR 加载到当前进程并返回运行时接口指针，如 ICLRRuntimeHost、 ICLRStrongName 和 IMetaDataDispenser。 此方法将取代所有 CorBindTo\* 函数。
>
> ### ICLRRuntimeHost 接口 
>
> 提供与 .NET Framework 版本1中提供的 ICorRuntimeHost 接口类似的功能，其中包含以下更改： 用于设置宿主控件接口的 SetHostControl 方法的添加。 省略提供的某些方法 ICorRuntimeHost 。
>
> Start 方法  
> 将 CLR 初始化为一个进程。
>
> ExecuteInDefaultAppDomain 方法 在指定的程序集中调用指定类型的指定方法。

## 流程A\(硬盘加载\)

1. 初始化ICLRMetaHost接口。
2. 通过ICLRMetaHost获取ICLRRuntimeInfo接口。
3. 通过ICLRRuntimeInfo将 CLR 加载到当前进程并返回运行时接口ICLRRuntimeHost指针。
4. 通过ICLRRuntimeHost.Start\(\)初始化CLR。
5. 通过ICLRRuntimeHost.EecuteInDefaultAppDomain执行指定程序集\(硬盘上\)。

## 实现

{% tabs %}
{% tab title="unmanaged.cpp" %}
```cpp
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

int main()
{
    ICLRMetaHost* iMetaHost = NULL;
    ICLRRuntimeInfo* iRuntimeInfo = NULL;
    ICLRRuntimeHost* iRuntimeHost = NULL;

    //初始化环境
    CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&iMetaHost);
    iMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&iRuntimeInfo);
    iRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&iRuntimeHost);
    iRuntimeHost->Start();

    //执行
    iRuntimeHost->ExecuteInDefaultAppDomain(L"C:\\Users\\Black Sheep\\source\\repos\\HostingCLR\\TEST\\bin\\Debug\\TEST.exe", L"TEST.Program", L"print", L"test", NULL);

    //释放
    iRuntimeInfo->Release();
    iMetaHost->Release();
    iRuntimeHost->Release();

    return 0;
};
```
{% endtab %}

{% tab title="managed.cs" %}
```csharp
using System;

namespace TEST
{
    class Program
    {
        static int Main(String[] args)
        {

            return 1;
        }
        static int print(String strings)
        {
            Console.WriteLine(strings);
            return 1;
        }
    }
}
```
{% endtab %}
{% endtabs %}

![](../.gitbook/assets/image%20%28221%29.png)

## 流程B\(内存加载\)

1.初始化CLR环境\(同上\)

```text
	CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (VOID**)&iMetaHost);
	iMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (VOID**)&iRuntimeInfo);
	iRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&iRuntimeHost);
	iRuntimeHost->Start();
```

2.通过ICLRRuntimeHost获取\_AppDomain接口指针，然后通过\_AppDomain接口的QueryInterface方法来查询默认应用程序域的实例指针。

```text
	iRuntimeHost->GetDefaultDomain(&pAppDomain);
	pAppDomain->QueryInterface(__uuidof(_AppDomain), (VOID**)&pDefaultAppDomain);

```

3.通过默认应用程序域实例的Load\_3方法加载安全.net程序集数组，并返回Assembly的实例对象指针，通过Assembly实例对象的get\_EntryPoint方法获取描述入口点的MethodInfo实例对象。

```text
	saBound[0].cElements = ASSEMBLY_LENGTH;
	saBound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, saBound);

	SafeArrayAccessData(pSafeArray, &pData);
	memcpy(pData, dotnetRaw, ASSEMBLY_LENGTH);
	SafeArrayUnaccessData(pSafeArray);

	pDefaultAppDomain->Load_3(pSafeArray, &pAssembly);
	pAssembly->get_EntryPoint(&pMethodInfo);
```

4.创建参数安全数组

```text
ZeroMemory(&vRet, sizeof(VARIANT));
	ZeroMemory(&vObj, sizeof(VARIANT));
	vObj.vt = VT_NULL;

	vPsa.vt = (VT_ARRAY | VT_BSTR);
	args = SafeArrayCreateVector(VT_VARIANT, 0, 1);

	if (argc > 1)
	{
		vPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argc);
		for (long i = 0; i < argc; i++)
		{
			SafeArrayPutElement(vPsa.parray, &i, SysAllocString(argv[i]));
		}

		long idx[1] = { 0 };
		SafeArrayPutElement(args, idx, &vPsa);
	}

```

5.通过描述入口点的MethodInfo实例对象的Invoke方法执行入口点。

```text
HRESULT hr = pMethodInfo->Invoke_3(vObj, args, &vRet);
```

### 完整代码

{% tabs %}
{% tab title="unmanaged.cpp" %}
```cpp
#include <stdio.h>
#include <tchar.h>
#include <metahost.h>
#pragma comment(lib, "mscoree.lib")

#import <mscorlib.tlb> raw_interfaces_only			\
    	high_property_prefixes("_get","_put","_putref")		\
    	rename("ReportEvent", "InteropServices_ReportEvent")	\
	rename("or", "InteropServices_or")

using namespace mscorlib;
#define ASSEMBLY_LENGTH  8192


unsigned char dotnetRaw[8192] =
"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00...";//.net程序集字节数组



int _tmain(int argc, _TCHAR* argv[])
{

	ICLRMetaHost* iMetaHost = NULL;
	ICLRRuntimeInfo* iRuntimeInfo = NULL;
	ICorRuntimeHost* iRuntimeHost = NULL;
	IUnknownPtr pAppDomain = NULL;
	_AppDomainPtr pDefaultAppDomain = NULL;
	_AssemblyPtr pAssembly = NULL;
	_MethodInfoPtr pMethodInfo = NULL;
	SAFEARRAYBOUND saBound[1];
	void* pData = NULL;
	VARIANT vRet;
	VARIANT vObj;
	VARIANT vPsa;
	SAFEARRAY* args = NULL;

	CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (VOID**)&iMetaHost);
	iMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (VOID**)&iRuntimeInfo);
	iRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&iRuntimeHost);
	iRuntimeHost->Start();


	iRuntimeHost->GetDefaultDomain(&pAppDomain);
	pAppDomain->QueryInterface(__uuidof(_AppDomain), (VOID**)&pDefaultAppDomain);

	saBound[0].cElements = ASSEMBLY_LENGTH;
	saBound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, saBound);

	SafeArrayAccessData(pSafeArray, &pData);
	memcpy(pData, dotnetRaw, ASSEMBLY_LENGTH);
	SafeArrayUnaccessData(pSafeArray);

	pDefaultAppDomain->Load_3(pSafeArray, &pAssembly);
	pAssembly->get_EntryPoint(&pMethodInfo);

	ZeroMemory(&vRet, sizeof(VARIANT));
	ZeroMemory(&vObj, sizeof(VARIANT));
	vObj.vt = VT_NULL;



	vPsa.vt = (VT_ARRAY | VT_BSTR);
	args = SafeArrayCreateVector(VT_VARIANT, 0, 1);

	if (argc > 1)
	{
		vPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, argc);
		for (long i = 0; i < argc; i++)
		{
			SafeArrayPutElement(vPsa.parray, &i, SysAllocString(argv[i]));
		}

		long idx[1] = { 0 };
		SafeArrayPutElement(args, idx, &vPsa);
	}

	HRESULT hr = pMethodInfo->Invoke_3(vObj, args, &vRet);
	pMethodInfo->Release();
	pAssembly->Release();
	pDefaultAppDomain->Release();
	iRuntimeInfo->Release();
	iMetaHost->Release();
	CoUninitialize();

	return 0;
};

```
{% endtab %}

{% tab title="managed.cs" %}
```csharp
using System;

namespace TEST
{
    class Program
    {
        static int Main(String[] args)
        {
            Console.WriteLine("hello world!");
            foreach (var s in args)
            {
                Console.WriteLine(s);
            }
            return 1;
        }
    }
}
```
{% endtab %}
{% endtabs %}

![](../.gitbook/assets/image%20%28222%29.png)

![](../.gitbook/assets/image%20%28223%29.png)

## LINKS

{% embed url="https://teamhydra.blog/2020/10/12/in-process-execute-assembly-and-mail-slots/" %}

{% embed url="https://docs.microsoft.com/" %}

{% embed url="https://b4rtik.github.io/posts/execute-assembly-via-meterpreter-session/" %}

{% embed url="https://b4rtik.github.io/posts/execute-assembly-via-meterpreter-session-part-2/" %}







