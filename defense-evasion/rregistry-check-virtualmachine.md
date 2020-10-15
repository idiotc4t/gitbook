# 基于Registry的虚拟机检测

## 简介

通常在编写的恶意软件会被蓝队捕捉，那么如何让蓝队花去更长时间去反编译我们的恶意软件这也成为了一种必选项，注意不是防止破解，理论上任何软件都会被破解，我们需要做的其实只是增加蓝队的破解成本。

通常蓝队会把捕捉到的恶意软件放在一个虚拟环境里如vmware，virtualbox等知名虚拟机软件，也有可能是自研的沙箱，那么如何识别软件是否运行在虚拟环境里会是防止破解重要的一环，本文将叙述一部分常见的虚拟机软件会注册的Registry，检测虚拟机防止破解以便让蓝队成员增加破解成本。

## 检测原理

通常在虚拟内，虚拟机软件会注册一些在物理机上不存在的注册表项，如果在注册表内出现了这样的选项，基本可以判定为运行在虚拟机环境，当然这种判断也有误报的可能，一些虚拟机软件会在物理界也注册一些相同的选项，但是对于虚拟机内，这样的表项算是比较少。

通常注册表项会使用windows提供的api进行查询，会使用让如下函数：

ntdll.dll导出:

* NtOpenKey
* NtEnumerateKey
* NtQueryValueKey
* NtClose

以及在其之上封装出的kernel32.dll的导出函数:

* RegOpenKey
* RegOpenKeyEx
* RegQueryValue
* RegQueryValueEx
* RegCloseKey
* RegEnumKeyEx

## 检查注册表路径

代码来自:[https://github.com/a0rtega/pafish](https://github.com/a0rtega/pafish)

```text
/* sample of usage: see detection of VirtualBox in the table below to check registry path */
int vbox_reg_key7() {
    return pafish_exists_regkey(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\VBOX__");
}

/* code is taken from "pafish" project, see references on the parent page */
int pafish_exists_regkey(HKEY hKey, char * regkey_s) {
    HKEY regkey;
    LONG ret;

    /* regkey_s == "HARDWARE\\ACPI\\FADT\\VBOX__"; */
    if (pafish_iswow64()) {
        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
    }
    else {
        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ, &regkey);
    }

    if (ret == ERROR_SUCCESS) {
        RegCloseKey(regkey);
        return TRUE;
    }
    else
        return FALSE;
}
```

对于蓝队，如果注册表查询中出现了如下表项，那么该软件可能就在使用逃避技术。

| Detect | Registry path | Details \(if any\) |
| :--- | :--- | :--- |
| \[general\] | HKLM\Software\Classes\Folder\shell\sandbox |  |
| Hyper-V | HKLM\SOFTWARE\Microsoft\Hyper-V |  |
|  | HKLM\SOFTWARE\Microsoft\VirtualMachine |  |
|  | HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters | Usually "HostName" and "VirtualMachineName" values are read under this path |
|  | HKLM\SYSTEM\ControlSet001\Services\vmicheartbeat |  |
|  | HKLM\SYSTEM\ControlSet001\Services\vmicvss |  |
|  | HKLM\SYSTEM\ControlSet001\Services\vmicshutdown |  |
|  | HKLM\SYSTEM\ControlSet001\Services\vmicexchange |  |
| Parallels | HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN\_1AB8\* | Subkey has the following structure: VEN\_XXXX&DEV\_YYYY&SUBSYS\_ZZZZ&REV\_WW |
| Sandboxie | HKLM\SYSTEM\CurrentControlSet\Services\SbieDrv |  |
|  | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sandboxie |  |
| VirtualBox | HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN\_80EE\* | Subkey has the following structure: VEN\_XXXX&DEV\_YYYY&SUBSYS\_ZZZZ&REV\_WW |
|  | HKLM\HARDWARE\ACPI\DSDT\VBOX\_\_ |  |
|  | HKLM\HARDWARE\ACPI\FADT\VBOX\_\_ |  |
|  | HKLM\HARDWARE\ACPI\RSDT\VBOX\_\_ |  |
|  | HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions |  |
|  | HKLM\SYSTEM\ControlSet001\Services\VBoxGuest |  |
|  | HKLM\SYSTEM\ControlSet001\Services\VBoxMouse |  |
|  | HKLM\SYSTEM\ControlSet001\Services\VBoxService |  |
|  | HKLM\SYSTEM\ControlSet001\Services\VBoxSF |  |
|  | HKLM\SYSTEM\ControlSet001\Services\VBoxVideo |  |
| VirtualPC | HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN\_5333\* | Subkey has the following structure: VEN\_XXXX&DEV\_YYYY&SUBSYS\_ZZZZ&REV\_WW |
|  | HKLM\SYSTEM\ControlSet001\Services\vpcbus |  |
|  | HKLM\SYSTEM\ControlSet001\Services\vpc-s3 |  |
|  | HKLM\SYSTEM\ControlSet001\Services\vpcuhub |  |
|  | HKLM\SYSTEM\ControlSet001\Services\msvmmouf |  |
| VMware | HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN\_15AD\* | Subkey has the following structure: VEN\_XXXX&DEV\_YYYY&SUBSYS\_ZZZZ&REV\_WW |
|  | HKCU\SOFTWARE\VMware, Inc.\VMware Tools |  |
|  | HKLM\SOFTWARE\VMware, Inc.\VMware Tools |  |
|  | HKLM\SYSTEM\ControlSet001\Services\vmdebug |  |
|  | HKLM\SYSTEM\ControlSet001\Services\vmmouse |  |
|  | HKLM\SYSTEM\ControlSet001\Services\VMTools |  |
|  | HKLM\SYSTEM\ControlSet001\Services\VMMEMCTL |  |
|  | HKLM\SYSTEM\ControlSet001\Services\vmware |  |
|  | HKLM\SYSTEM\ControlSet001\Services\vmci |  |
|  | HKLM\SYSTEM\ControlSet001\Services\vmx86 |  |
|  | HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar\_VMware\_IDE\_CD\* |  |
|  | HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar\_VMware\_SATA\_CD\* |  |
|  | HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware\_Virtual\_IDE\_Hard\_Drive\* |  |
|  | HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware\_Virtual\_SATA\_Hard\_Drive\* |  |
| Wine | HKCU\SOFTWARE\Wine |  |
|  | HKLM\SOFTWARE\Wine |  |
| Xen | HKLM\HARDWARE\ACPI\DSDT\xen |  |
|  | HKLM\HARDWARE\ACPI\FADT\xen |  |
|  | HKLM\HARDWARE\ACPI\RSDT\xen |  |
|  | HKLM\SYSTEM\ControlSet001\Services\xenevtchn |  |
|  | HKLM\SYSTEM\ControlSet001\Services\xennet |  |
|  | HKLM\SYSTEM\ControlSet001\Services\xennet6 |  |
|  | HKLM\SYSTEM\ControlSet001\Services\xensvc |  |
|  | HKLM\SYSTEM\ControlSet001\Services\xenvdb |  |

## 检查特定的表项内的字符串

```text
/* sample of usage: see detection of VirtualBox in the table below to check registry path and key values */
int vbox_reg_key2() {
    return pafish_exists_regkey_value_str(HKEY_LOCAL_MACHINE, "HARDWARE\\Description\\System", "SystemBiosVersion", "VBOX");
}

/* code is taken from "pafish" project, see references on the parent page */
int pafish_exists_regkey_value_str(HKEY hKey, char * regkey_s, char * value_s, char * lookup) {
    /*
        regkey_s == "HARDWARE\\Description\\System";
        value_s == "SystemBiosVersion";
        lookup == "VBOX";
    */

    HKEY regkey;
    LONG ret;
    DWORD size;
    char value[1024], * lookup_str;
    size_t lookup_size;

    lookup_size = strlen(lookup);
    lookup_str = malloc(lookup_size+sizeof(char));
    strncpy(lookup_str, lookup, lookup_size+sizeof(char));
    size = sizeof(value);

    /* regkey_s == "HARDWARE\\Description\\System"; */
    if (pafish_iswow64()) {
        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
    }
    else {
        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ, &regkey);
    }

    if (ret == ERROR_SUCCESS) {
        /* value_s == "SystemBiosVersion"; */
        ret = RegQueryValueEx(regkey, value_s, NULL, NULL, (BYTE*)value, &size);
        RegCloseKey(regkey);

        if (ret == ERROR_SUCCESS) {
            size_t i;
            for (i = 0; i < strlen(value); i++) { /* case-insensitive */
                value[i] = toupper(value[i]);
            }
            for (i = 0; i < lookup_size; i++) { /* case-insensitive */
                lookup_str[i] = toupper(lookup_str[i]);
            }
            if (strstr(value, lookup_str) != NULL) {
                free(lookup_str);
                return TRUE;
            }
        }
    }

    free(lookup_str);
    return FALSE;
}
```



| Detect | Registry path | Registry key | String |
| :--- | :--- | :--- | :--- |
| \[general\] | HKLM\HARDWARE\Description\System | SystemBiosDate | 06/23/99 |
|  | HKLM\HARDWARE\Description\System\BIOS | SystemProductName | A M I |
| BOCHS | HKLM\HARDWARE\Description\System | SystemBiosVersion | BOCHS |
|  | HKLM\HARDWARE\Description\System | VideoBiosVersion | BOCHS |
| Anubis | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion | ProductID | 76487-337-8429955-22614 |
|  | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion | ProductID | 76487-337-8429955-22614 |
| CwSandbox | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion | ProductID | 76487-644-3177037-23510 |
|  | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion | ProductID | 76487-644-3177037-23510 |
| JoeBox | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion | ProductID | 55274-640-2673064-23950 |
|  | HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion | ProductID | 55274-640-2673064-23950 |
| Parallels | HKLM\HARDWARE\Description\System | SystemBiosVersion | PARALLELS |
|  | HKLM\HARDWARE\Description\System | VideoBiosVersion | PARALLELS |
| QEMU | HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0 | Identifier | QEMU |
|  | HKLM\HARDWARE\Description\System | SystemBiosVersion | QEMU |
|  | HKLM\HARDWARE\Description\System | VideoBiosVersion | QEMU |
|  | HKLM\HARDWARE\Description\System\BIOS | SystemManufacturer | QEMU |
| VirtualBox | HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0 | Identifier | VBOX |
|  | HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0 | Identifier | VBOX |
|  | HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0 | Identifier | VBOX |
|  | HKLM\HARDWARE\Description\System | SystemBiosVersion | VBOX |
|  | HKLM\HARDWARE\Description\System | VideoBiosVersion | VIRTUALBOX |
|  | HKLM\HARDWARE\Description\System\BIOS | SystemProductName | VIRTUAL |
|  | HKLM\SYSTEM\ControlSet001\Services\Disk\Enum | DeviceDesc | VBOX |
|  | HKLM\SYSTEM\ControlSet001\Services\Disk\Enum | FriendlyName | VBOX |
|  | HKLM\SYSTEM\ControlSet002\Services\Disk\Enum | DeviceDesc | VBOX |
|  | HKLM\SYSTEM\ControlSet002\Services\Disk\Enum | FriendlyName | VBOX |
|  | HKLM\SYSTEM\ControlSet003\Services\Disk\Enum | DeviceDesc | VBOX |
|  | HKLM\SYSTEM\ControlSet003\Services\Disk\Enum | SystemProductName | VBOX |
|  | HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation | SystemProductName | VIRTUAL |
|  | HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation | SystemProductName | VIRTUALBOX |
| VMware | HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0 | Identifier | VMWARE |
|  | HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0 | Identifier | VMWARE |
|  | HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0 | Identifier | VMWARE |
|  | HKLM\HARDWARE\Description\System | SystemBiosVersion | VMWARE |
|  | HKLM\HARDWARE\Description\System | SystemBiosVersion | INTEL - 6040000 |
|  | HKLM\HARDWARE\Description\System | VideoBiosVersion | VMWARE |
|  | HKLM\HARDWARE\Description\System\BIOS | SystemProductName | VMware |
|  | HKLM\SYSTEM\ControlSet001\Services\Disk\Enum | 0 | VMware |
|  | HKLM\SYSTEM\ControlSet001\Services\Disk\Enum | 1 | VMware |
|  | HKLM\SYSTEM\ControlSet001\Services\Disk\Enum | DeviceDesc | VMware |
|  | HKLM\SYSTEM\ControlSet001\Services\Disk\Enum | FriendlyName | VMware |
|  | HKLM\SYSTEM\ControlSet002\Services\Disk\Enum | DeviceDesc | VMware |
|  | HKLM\SYSTEM\ControlSet002\Services\Disk\Enum | FriendlyName | VMware |
|  | HKLM\SYSTEM\ControlSet003\Services\Disk\Enum | DeviceDesc | VMware |
|  | HKLM\SYSTEM\ControlSet003\Services\Disk\Enum | FriendlyName | VMware |
|  | HKCR\Installer\Products | ProductName | vmware tools |
|  | HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | DisplayName | vmware tools |
|  | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | DisplayName | vmware tools |
|  | HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall | DisplayName | vmware tools |
|  | HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000 | CoInstallers32 |  |
|  | HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000 | DriverDesc | VMware\* |
|  | HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000 | InfSection | vmx\* |
|  | HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000 | ProviderName | VMware\* |
|  | HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000\Settings | Device Description | VMware\* |
|  | HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation | SystemProductName | VMWARE |
|  | HKLM\SYSTEM\CurrentControlSet\Control\Video\{GUID}\Video | Service | vm3dmp |
|  | HKLM\SYSTEM\CurrentControlSet\Control\Video\{GUID}\Video | Service | vmx\_svga |
|  | HKLM\SYSTEM\CurrentControlSet\Control\Video\{GUID}\0000 | Device Description | VMware SVGA\* |
| Xen | HKLM\HARDWARE\Description\System\BIOS | SystemProductName | Xen |

## LINKS

{% embed url="https://github.com/a0rtega/pafish" %}

{% embed url="https://evasions.checkpoint.com/techniques/registry.html" %}



