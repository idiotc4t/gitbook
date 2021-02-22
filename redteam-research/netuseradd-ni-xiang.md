# NetUserAdd逆向

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
	PACL Dacl = NULL;
	PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
	PACL SamDacl{ 0 };
	PACL LocalDacl = { 0 };
	BOOLEAN Defaulted;
	BOOLEAN Present;
	ACL_SIZE_INFORMATION AclSize;

	hSamlib = LoadLibraryA("samlib.dll");
	hNtdll = LoadLibraryA("ntdll");

	pSamConnect SamConnect = (pSamConnect)GetProcAddress(hSamlib, "SamConnect");
	pSamOpenDomain SamOpenDomain = (pSamOpenDomain)GetProcAddress(hSamlib, "SamOpenDomain");
	pSamCreateUser2InDomain SamCreateUser2InDomain = (pSamCreateUser2InDomain)GetProcAddress(hSamlib, "SamCreateUser2InDomain");
	pSamSetInformationUser SamSetInformationUser = (pSamSetInformationUser)GetProcAddress(hSamlib, "SamSetInformationUser");
	pSamQuerySecurityObject SamQuerySecurityObject = (pSamQuerySecurityObject)GetProcAddress(hSamlib, "SamQuerySecurityObject");
	pRtlInitUnicodeString RtlInitUnicodeString = (pRtlInitUnicodeString)GetProcAddress(hNtdll, "RtlInitUnicodeString");
	pRtlGetDaclSecurityDescriptor RtlGetDaclSecurityDescriptor = (pRtlGetDaclSecurityDescriptor)GetProcAddress(hNtdll, "RtlGetDaclSecurityDescriptor");
	pRtlQueryInformationAcl RtlQueryInformationAcl = (pRtlQueryInformationAcl)GetProcAddress(hNtdll, "RtlQueryInformationAcl");

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

