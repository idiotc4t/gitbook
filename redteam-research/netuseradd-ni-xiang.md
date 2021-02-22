# NetUserAdd逆向

## 起因

![](../.gitbook/assets/image%20%28266%29.png)

## 过程

反手直接拖ida。

![](../.gitbook/assets/image%20%28273%29.png)

![](../.gitbook/assets/image%20%28261%29.png)

跟了下逻辑然后对比了下React OS发现逻辑几乎一致，那直接扣代码。

![](../.gitbook/assets/image%20%28268%29.png)

win10上UaspOpenDomain没有导出，可以使用特征码搜索的方式去调用，这里跟进了发现同样是调用了sam系函数。

![](../.gitbook/assets/image%20%28262%29.png)

跟一下函数还需要sid。

![](../.gitbook/assets/image%20%28260%29.png)

![](../.gitbook/assets/image%20%28272%29.png)

发现是由 [LsaQueryInformationPolicy](https://doxygen.reactos.org/d8/d29/dll_2win32_2advapi32_2sec_2lsa_8c.html#a7d14043215b57c248b75f13ae80adde9)的获取，这个函数在ntsecapi.h里有描述，直接拿来用就好了。

至此用户创建完成，然后通过SetUserInfo设置密码，同样这个函数在windows 10上没有导出。

![](../.gitbook/assets/image%20%28265%29.png)

![](../.gitbook/assets/image%20%28271%29.png)

跟一下，发现下层函数一致并导出。

![](../.gitbook/assets/image%20%28270%29.png)

![](../.gitbook/assets/image%20%28263%29.png)

![](../.gitbook/assets/image%20%28257%29.png)

跟踪了一下函数逻辑，发现不同的UserInfo都有不同的处理方法，通常我们会传入一个USERINFO1结构体，这里会把有效信息传入到一个 USER\_ALL\_INFORMATION 结构体里面，这个结构体的实现和Startupinfo有点像，需要同时设置值和使用标签位，阅读发现，有一个结构体单处理密码。

![](../.gitbook/assets/image%20%28274%29.png)

![](../.gitbook/assets/image%20%28269%29.png)

这里我们只需要传入密码，然后将标志位设1。

我们就自己封装出了一个NetUserAdd。

## 完整代码

```text
#include "ApiAddUser.h"



int wmain(int argc, wchar_t* argv[])
{
	UNICODE_STRING UserName;
	UNICODE_STRING PassWord;
	HANDLE ServerHandle = NULL;
	HANDLE DomainHandle = NULL;
	HANDLE UserHandle = NULL;
	ULONG GrantedAccess;
	ULONG RelativeId;
	NTSTATUS Status = NULL;
	HMODULE hSamlib = NULL;
	HMODULE hNtdll = NULL;
	HMODULE hNetapi32 = NULL;
	LSA_HANDLE hPolicy = NULL;
	LSA_OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	PPOLICY_ACCOUNT_DOMAIN_INFO DomainInfo = NULL;
	USER_ALL_INFORMATION uai = { 0 };


	hSamlib = LoadLibraryA("samlib.dll");
	hNtdll = LoadLibraryA("ntdll");

	pSamConnect SamConnect = (pSamConnect)GetProcAddress(hSamlib, "SamConnect");
	pSamOpenDomain SamOpenDomain = (pSamOpenDomain)GetProcAddress(hSamlib, "SamOpenDomain");
	pSamCreateUser2InDomain SamCreateUser2InDomain = (pSamCreateUser2InDomain)GetProcAddress(hSamlib, "SamCreateUser2InDomain");
	pSamSetInformationUser SamSetInformationUser = (pSamSetInformationUser)GetProcAddress(hSamlib, "SamSetInformationUser");
	pSamQuerySecurityObject SamQuerySecurityObject = (pSamQuerySecurityObject)GetProcAddress(hSamlib, "SamQuerySecurityObject");
	pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");

	RtlInitUnicodeString(&UserName, L"Admin");
	RtlInitUnicodeString(&PassWord, L"Admin");

	Status = SamConnect(NULL, &ServerHandle, SAM_SERVER_CONNECT | SAM_SERVER_LOOKUP_DOMAIN, NULL);;
	Status = LsaOpenPolicy(NULL,&ObjectAttributes,POLICY_VIEW_LOCAL_INFORMATION,&hPolicy);
	Status = LsaQueryInformationPolicy(hPolicy, PolicyAccountDomainInformation, (PVOID*)&DomainInfo);

	Status = SamOpenDomain(ServerHandle, 
		DOMAIN_CREATE_USER | DOMAIN_LOOKUP | DOMAIN_READ_PASSWORD_PARAMETERS, 
		DomainInfo->DomainSid, 
		&DomainHandle);

	Status = SamCreateUser2InDomain(DomainHandle,
		&UserName,
		USER_NORMAL_ACCOUNT,
		USER_ALL_ACCESS | DELETE | WRITE_DAC,
		&UserHandle,&GrantedAccess,&RelativeId);

	RtlInitUnicodeString(&uai.NtPassword, PassWord.Buffer);
	uai.NtPasswordPresent = TRUE;
	uai.WhichFields |= USER_ALL_NTPASSWORDPRESENT;


	Status = SamSetInformationUser(UserHandle,
		UserAllInformation,
		&uai);

	return 0;
}
```

