# COM组件相关的武器化开发技术

## COM简介

> 由于网上关于直接调用windows内建com组件的编程技术比较稀少\(至少我找了几天没找到\)，该文会简要介绍如何通过已知clsid在自定可执行文件中调用windows com接口，实现部分武器化技术。

{% hint style="danger" %}
文旨在简单介绍调用windows本身com组件的相关编程技术，由于本人非职业开发，理解可能存在一定偏差，如发现有明显错误，请务必直接联系本人\(防止误人子弟略略略略略\)。
{% endhint %}

阅读本文的朋友很大概率经常使用诸如atexec、wmiexec之类的横向移动工具，该类技术其实质也是对dcom\(分布式com\)组件的调用。

com本身是一种开发理念，旨在跨应用和语言共享二进制代码，其理念类似dll，但dll仅能被C/C++理解或遵循C调用规范的语言使用,com通过指明二进制模块必须编译成约定的结构解决了这个问题，其实现方式与c++的类相似，所以通常使用c++来实现一个com组件。

就windows中实现来看，com组件本身仍旧是标准的pe结构\(dll/exe\)，只不过其内部包含了coclass，以及在注册表中注册了相关键值，以便我们找到并使用它。

## 原理

通常windows内建com已经在注册表内存储着相关信息，而自定义com需要创建注册表入口点告诉windows com组件服务器在上面位置，这个过程称之为注册\(Registration\)，我们可以在HKEY\_CLASSES\_ROOT\CLSID\{clsid}位置找到所有windows已注册的com组件。

![](../.gitbook/assets/image%20%28170%29.png)

注册后com通过GUID\(globally unique identifier\)唯一标识符来寻找并使用这个com组件，理论上每一个GUID\(有时也称UUID\)都是唯一的,GUID在标识不同的对象时会有不同的称呼，标识类对象时称之为CLSID\(类标识符\)、标识接口时被称为IID\(接口标识符\)。

在每一个注册的clsid表项中都包含一个名为InprocServer32的子项，该子项内存有映射到该com二进制文件的键值对，操作系统通过该键值对将com组件载入进程或另起进程。\(进程内组件和进程外组件，二进制代码的表现形式为dll\(内\)和exe\(外\)\)。

![](../.gitbook/assets/image%20%28176%29.png)

我们可以通过以下powershell代码遍历所有com组件和它导出的方法。

```text
New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR
Get-ChildItem -Path HKCR:\CLSID -Name | Select -Skip 1 > clsids.txt

$Position  = 1
$Filename = "win10-clsid-members.txt"
$inputFilename = "clsids.txt"
ForEach($CLSID in Get-Content $inputFilename) {
      Write-Output "$($Position) - $($CLSID)"
      Write-Output "------------------------" | Out-File $Filename -Append
      Write-Output $($CLSID) | Out-File $Filename -Append
      $handle = [activator]::CreateInstance([type]::GetTypeFromCLSID($CLSID))
      $handle | Get-Member | Out-File $Filename -Append
      $Position += 1
}
```

## 通过C++实现调用

通常对com组件的利用很多文章都直接使用powershell代码调用接口，代码如下:

```text
$handle = [activator]::CreateInstance([type]::GetTypeFromCLSID("xxx"))
$handle.shellxec('cmd.exe /c')
```

在这里我会介绍一种通过c++调用的方法，在介绍之前，先看一个简单的powershell案例，Charles Hamilton发现prchauto.dll拥有一个ProcessChain的类，该类公开的start方法和commdline属性。

![](../.gitbook/assets/image%20%28174%29.png)

接下来我们通过部分工具将这个简单案例使用c艹实现，我们先使用oleview打开这个com组件的实现文件。

![](../.gitbook/assets/image%20%28177%29.png)

可以看到processchain类导出了一个名为iprocesschain的接口，我们使用这个工具将这个类导出为IDL文件，然后使用MIDL工具将这个IDL文件转换成我们需要的C++的头文件，这个文件会定义这个类和接口的使用方法。

![](../.gitbook/assets/image%20%28178%29.png)

使用MIDL，生成的processchain.h就是我们需要的。

![](../.gitbook/assets/image%20%28171%29.png)

![](../.gitbook/assets/image%20%28175%29.png)

部分代码:

```text

EXTERN_C const IID IID_IProcessChain;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("79ED9CB4-3A01-4ABA-AD3C-A985EE298B20")
    IProcessChain : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_ExecutablePath( 
            /* [retval][out] */ BSTR *ExecutablePath) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_ExecutablePath( 
            /* [in] */ BSTR ExecutablePath) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_CommandLine( 
            /* [retval][out] */ BSTR *CommandLine) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_CommandLine( 
            /* [in] */ BSTR CommandLine) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_NonBlocking( 
            /* [retval][out] */ VARIANT_BOOL *NonBlocking) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_NonBlocking( 
            /* [in] */ VARIANT_BOOL NonBlocking) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_TimeoutPeriod( 
            /* [retval][out] */ long *TimeoutPeriod) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_TimeoutPeriod( 
            /* [in] */ long TimeoutPeriod) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Start( 
            /* [out] */ VARIANT_BOOL *TimerFired) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE CancelWait( void) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Terminate( void) = 0;
        
    };
```

接下来就是简单的编程实现了，如果我们能找到一个支持提权且能执行命令的com组件，那我们就又获得了一个新的bypassuac的方法。

## 代码

先贴实现效果:

![win10&#x7684;&#x8BA1;&#x7B97;&#x673A;&#x6709;&#x70B9;&#x5927;.jpg](../.gitbook/assets/image%20%28172%29.png)

### processchain.h

```text


/* this ALWAYS GENERATED file contains the definitions for the interfaces */


 /* File created by MIDL compiler version 8.01.0622 */
/* at Tue Jan 19 11:14:07 2038
 */
/* Compiler settings for .\prchauto.IDL:
    Oicf, W1, Zp8, env=Win32 (32b run), target_arch=X86 8.01.0622 
    protocol : dce , ms_ext, c_ext, robust
    error checks: allocation ref bounds_check enum stub_data 
    VC __declspec() decoration level: 
         __declspec(uuid()), __declspec(selectany), __declspec(novtable)
         DECLSPEC_UUID(), MIDL_INTERFACE()
*/
/* @@MIDL_FILE_HEADING(  ) *

#pragma warning( disable: 4049 )  /* more than 64k source lines */


/* verify that the <rpcndr.h> version is high enough to compile this file*/
#ifndef __REQUIRED_RPCNDR_H_VERSION__
#define __REQUIRED_RPCNDR_H_VERSION__ 475
#endif

#include "rpc.h"
#include "rpcndr.h"

#ifndef __RPCNDR_H_VERSION__
#error this stub requires an updated version of <rpcndr.h>
#endif /* __RPCNDR_H_VERSION__ */


#ifndef __processchain_h__
#define __processchain_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

/* Forward Declarations */ 

#ifndef ___IProcessChainEvents_FWD_DEFINED__
#define ___IProcessChainEvents_FWD_DEFINED__
typedef interface _IProcessChainEvents _IProcessChainEvents;

#endif 	/* ___IProcessChainEvents_FWD_DEFINED__ */


#ifndef __IProcessChain_FWD_DEFINED__
#define __IProcessChain_FWD_DEFINED__
typedef interface IProcessChain IProcessChain;

#endif 	/* __IProcessChain_FWD_DEFINED__ */


#ifndef __ProcessChain_FWD_DEFINED__
#define __ProcessChain_FWD_DEFINED__

#ifdef __cplusplus
typedef class ProcessChain ProcessChain;
#else
typedef struct ProcessChain ProcessChain;
#endif /* __cplusplus */

#endif 	/* __ProcessChain_FWD_DEFINED__ */


#ifdef __cplusplus
extern "C"{
#endif 



#ifndef __ProcessChainLib_LIBRARY_DEFINED__
#define __ProcessChainLib_LIBRARY_DEFINED__

/* library ProcessChainLib */
/* [version][uuid] */ 




EXTERN_C const IID LIBID_ProcessChainLib;

#ifndef ___IProcessChainEvents_DISPINTERFACE_DEFINED__
#define ___IProcessChainEvents_DISPINTERFACE_DEFINED__

/* dispinterface _IProcessChainEvents */
/* [uuid] */ 


EXTERN_C const IID DIID__IProcessChainEvents;

#if defined(__cplusplus) && !defined(CINTERFACE)

    MIDL_INTERFACE("85C4AF17-4C7A-4EF0-9BE7-39B06351AFA6")
    _IProcessChainEvents : public IDispatch
    {
    };
    
#else 	/* C style interface */

    typedef struct _IProcessChainEventsVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            _IProcessChainEvents * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            _IProcessChainEvents * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            _IProcessChainEvents * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            _IProcessChainEvents * This,
            /* [out] */ UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            _IProcessChainEvents * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            _IProcessChainEvents * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            _IProcessChainEvents * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        END_INTERFACE
    } _IProcessChainEventsVtbl;

    interface _IProcessChainEvents
    {
        CONST_VTBL struct _IProcessChainEventsVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define _IProcessChainEvents_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define _IProcessChainEvents_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define _IProcessChainEvents_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define _IProcessChainEvents_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define _IProcessChainEvents_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define _IProcessChainEvents_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define _IProcessChainEvents_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */


#endif 	/* ___IProcessChainEvents_DISPINTERFACE_DEFINED__ */


#ifndef __IProcessChain_INTERFACE_DEFINED__
#define __IProcessChain_INTERFACE_DEFINED__

/* interface IProcessChain */
/* [object][oleautomation][nonextensible][dual][uuid] */ 


EXTERN_C const IID IID_IProcessChain;

#if defined(__cplusplus) && !defined(CINTERFACE)
    
    MIDL_INTERFACE("79ED9CB4-3A01-4ABA-AD3C-A985EE298B20")
    IProcessChain : public IDispatch
    {
    public:
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_ExecutablePath( 
            /* [retval][out] */ BSTR *ExecutablePath) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_ExecutablePath( 
            /* [in] */ BSTR ExecutablePath) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_CommandLine( 
            /* [retval][out] */ BSTR *CommandLine) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_CommandLine( 
            /* [in] */ BSTR CommandLine) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_NonBlocking( 
            /* [retval][out] */ VARIANT_BOOL *NonBlocking) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_NonBlocking( 
            /* [in] */ VARIANT_BOOL NonBlocking) = 0;
        
        virtual /* [propget][id] */ HRESULT STDMETHODCALLTYPE get_TimeoutPeriod( 
            /* [retval][out] */ long *TimeoutPeriod) = 0;
        
        virtual /* [propput][id] */ HRESULT STDMETHODCALLTYPE put_TimeoutPeriod( 
            /* [in] */ long TimeoutPeriod) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Start( 
            /* [out] */ VARIANT_BOOL *TimerFired) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE CancelWait( void) = 0;
        
        virtual /* [id] */ HRESULT STDMETHODCALLTYPE Terminate( void) = 0;
        
    };
    
    
#else 	/* C style interface */

    typedef struct IProcessChainVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IProcessChain * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IProcessChain * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IProcessChain * This);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfoCount )( 
            IProcessChain * This,
            /* [out] */ UINT *pctinfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetTypeInfo )( 
            IProcessChain * This,
            /* [in] */ UINT iTInfo,
            /* [in] */ LCID lcid,
            /* [out] */ ITypeInfo **ppTInfo);
        
        HRESULT ( STDMETHODCALLTYPE *GetIDsOfNames )( 
            IProcessChain * This,
            /* [in] */ REFIID riid,
            /* [size_is][in] */ LPOLESTR *rgszNames,
            /* [range][in] */ UINT cNames,
            /* [in] */ LCID lcid,
            /* [size_is][out] */ DISPID *rgDispId);
        
        /* [local] */ HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IProcessChain * This,
            /* [annotation][in] */ 
            _In_  DISPID dispIdMember,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][in] */ 
            _In_  LCID lcid,
            /* [annotation][in] */ 
            _In_  WORD wFlags,
            /* [annotation][out][in] */ 
            _In_  DISPPARAMS *pDispParams,
            /* [annotation][out] */ 
            _Out_opt_  VARIANT *pVarResult,
            /* [annotation][out] */ 
            _Out_opt_  EXCEPINFO *pExcepInfo,
            /* [annotation][out] */ 
            _Out_opt_  UINT *puArgErr);
        
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_ExecutablePath )( 
            IProcessChain * This,
            /* [retval][out] */ BSTR *ExecutablePath);
        
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_ExecutablePath )( 
            IProcessChain * This,
            /* [in] */ BSTR ExecutablePath);
        
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_CommandLine )( 
            IProcessChain * This,
            /* [retval][out] */ BSTR *CommandLine);
        
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_CommandLine )( 
            IProcessChain * This,
            /* [in] */ BSTR CommandLine);
        
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_NonBlocking )( 
            IProcessChain * This,
            /* [retval][out] */ VARIANT_BOOL *NonBlocking);
        
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_NonBlocking )( 
            IProcessChain * This,
            /* [in] */ VARIANT_BOOL NonBlocking);
        
        /* [propget][id] */ HRESULT ( STDMETHODCALLTYPE *get_TimeoutPeriod )( 
            IProcessChain * This,
            /* [retval][out] */ long *TimeoutPeriod);
        
        /* [propput][id] */ HRESULT ( STDMETHODCALLTYPE *put_TimeoutPeriod )( 
            IProcessChain * This,
            /* [in] */ long TimeoutPeriod);
        
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Start )( 
            IProcessChain * This,
            /* [out] */ VARIANT_BOOL *TimerFired);
        
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *CancelWait )( 
            IProcessChain * This);
        
        /* [id] */ HRESULT ( STDMETHODCALLTYPE *Terminate )( 
            IProcessChain * This);
        
        END_INTERFACE
    } IProcessChainVtbl;

    interface IProcessChain
    {
        CONST_VTBL struct IProcessChainVtbl *lpVtbl;
    };

    

#ifdef COBJMACROS


#define IProcessChain_QueryInterface(This,riid,ppvObject)	\
    ( (This)->lpVtbl -> QueryInterface(This,riid,ppvObject) ) 

#define IProcessChain_AddRef(This)	\
    ( (This)->lpVtbl -> AddRef(This) ) 

#define IProcessChain_Release(This)	\
    ( (This)->lpVtbl -> Release(This) ) 


#define IProcessChain_GetTypeInfoCount(This,pctinfo)	\
    ( (This)->lpVtbl -> GetTypeInfoCount(This,pctinfo) ) 

#define IProcessChain_GetTypeInfo(This,iTInfo,lcid,ppTInfo)	\
    ( (This)->lpVtbl -> GetTypeInfo(This,iTInfo,lcid,ppTInfo) ) 

#define IProcessChain_GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId)	\
    ( (This)->lpVtbl -> GetIDsOfNames(This,riid,rgszNames,cNames,lcid,rgDispId) ) 

#define IProcessChain_Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr)	\
    ( (This)->lpVtbl -> Invoke(This,dispIdMember,riid,lcid,wFlags,pDispParams,pVarResult,pExcepInfo,puArgErr) ) 


#define IProcessChain_get_ExecutablePath(This,ExecutablePath)	\
    ( (This)->lpVtbl -> get_ExecutablePath(This,ExecutablePath) ) 

#define IProcessChain_put_ExecutablePath(This,ExecutablePath)	\
    ( (This)->lpVtbl -> put_ExecutablePath(This,ExecutablePath) ) 

#define IProcessChain_get_CommandLine(This,CommandLine)	\
    ( (This)->lpVtbl -> get_CommandLine(This,CommandLine) ) 

#define IProcessChain_put_CommandLine(This,CommandLine)	\
    ( (This)->lpVtbl -> put_CommandLine(This,CommandLine) ) 

#define IProcessChain_get_NonBlocking(This,NonBlocking)	\
    ( (This)->lpVtbl -> get_NonBlocking(This,NonBlocking) ) 

#define IProcessChain_put_NonBlocking(This,NonBlocking)	\
    ( (This)->lpVtbl -> put_NonBlocking(This,NonBlocking) ) 

#define IProcessChain_get_TimeoutPeriod(This,TimeoutPeriod)	\
    ( (This)->lpVtbl -> get_TimeoutPeriod(This,TimeoutPeriod) ) 

#define IProcessChain_put_TimeoutPeriod(This,TimeoutPeriod)	\
    ( (This)->lpVtbl -> put_TimeoutPeriod(This,TimeoutPeriod) ) 

#define IProcessChain_Start(This,TimerFired)	\
    ( (This)->lpVtbl -> Start(This,TimerFired) ) 

#define IProcessChain_CancelWait(This)	\
    ( (This)->lpVtbl -> CancelWait(This) ) 

#define IProcessChain_Terminate(This)	\
    ( (This)->lpVtbl -> Terminate(This) ) 

#endif /* COBJMACROS */


#endif 	/* C style interface */




#endif 	/* __IProcessChain_INTERFACE_DEFINED__ */


EXTERN_C const CLSID CLSID_ProcessChain;

#ifdef __cplusplus

class DECLSPEC_UUID("E430E93D-09A9-4DC5-80E3-CBB2FB9AF28E")
ProcessChain;
#endif
#endif /* __ProcessChainLib_LIBRARY_DEFINED__ */

/* Additional Prototypes for ALL interfaces */

/* end of Additional Prototypes */

#ifdef __cplusplus
}
#endif

#endif



```

### main.cpp

```text
#include <Windows.h>
#include "processchain.h"
#include <objbase.h>
#include <stdio.h>
#include <strsafe.h>

//定义com组件使用的bool值，其实质是一个二short类型。
typedef short VARIANT_BOOL;
#define VARIANT_TRUE ((VARIANT_BOOL)-1)
#define VARIANT_FALSE ((VARIANT_BOOL)0)


#define CLSID_ProcessChain L"{E430E93D-09A9-4DC5-80E3-CBB2FB9AF28E}"
#define IID_IProcessChain  L"{79ED9CB4-3A01-4ABA-AD3C-A985EE298B20}"


int main(int argc, TCHAR* argv[])
{
	HRESULT hr = 0;
	CLSID clsidIProcessChain = { 0 };
	IID iidIProcessChain = { 0 };
	IProcessChain* ProcessChain = NULL;
	BOOL bRet = FALSE;
	
	CoInitialize(NULL);//初始化com环境

	CLSIDFromString(CLSID_ProcessChain, &clsidIProcessChain);
	IIDFromString(IID_IProcessChain, &iidIProcessChain);
	//创建接口
	hr = CoCreateInstance(clsidIProcessChain, NULL, CLSCTX_INPROC_SERVER, iidIProcessChain, (LPVOID*)&ProcessChain);
	
	TCHAR cmd[] = L"C:\\WINDOWS\\system32\\calc.exe";
	VARIANT_BOOL b= VARIANT_TRUE;
//设置参数
	ProcessChain->put_CommandLine((BSTR)cmd);
	//调用方法
	hr = ProcessChain->Start(&b);
	
//释放
	CoUninitialize();
	return 0;
}
```

## LINKS

{% embed url="https://docs.microsoft.com/en-us/windows/win32/com/com-objects-and-interfaces" %}

{% embed url="https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects-part-two.html" %}

{% embed url="https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html" %}

> [https://dl.packetstormsecurity.net/papers/general/abusing-objects.pdf](https://dl.packetstormsecurity.net/papers/general/abusing-objects.pdf)



