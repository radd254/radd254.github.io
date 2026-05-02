---
title: '[Level-3]-RedLine'
date: 2026-03-15

---

# Lab Report - RedLine  
**DatHN5 - SO3 - FSAS**
---

Employ Volatility to analyze a memory dump, identifying suspicious processes, network IOCs, memory protections, and attacker's command-and-control infrastructure. 

**Category**: Endpoint Forensics 
**Tactics**: Privilege Escalation, Defense Evasion, Command and Control 
**Tools**: Volatility Strings

### Scenario

As a member of the Security Blue team, your assignment is to analyze a memory dump using Redline and Volatility tools. Your goal is to trace the steps taken by the attacker on the compromised machine and determine how they managed to bypass the Network Intrusion Detection System (NIDS). Your investigation will identify the specific malware family employed in the attack and its characteristics. Additionally, your task is to identify and mitigate any traces or footprints left by the attacker.

## Write up

### Q1 What is the name of the suspicious process?

Trước tiên mình xem đây là memory dump của máy chạy OS nào qua lệnh `file` và tool `volatility3` với plugin `windows.info`, kết quả cho thấy đây là memory dump của Windows.

![image](https://hackmd.io/_uploads/SJzi9yhY-g.png)

![image](https://hackmd.io/_uploads/rkelTy2Ybg.png)


Tiếp mình dùng plugin `windows.pstree` của `volatility3` để xem các tiến trình đáng ngờ đã chạy.

Ban đầu mình có để ý mấy tiến trình lạ lạ như hai hình bên dưới trong đó có `msedge.exe` mình tra cứu thì thấy nó cũng có khả năng là một tiến trình độc hại nhưng lại không phải đáp án thế nên mình nghĩ đó là EDGE real và bỏ qua. [Msedge.exe]([https://](https://lolbas-project.github.io/lolbas/Binaries/Msedge/))

![image](https://hackmd.io/_uploads/H1Wolx3YWe.png)

![image](https://hackmd.io/_uploads/r1G0glnY-x.png)

Ở cuối cùng của `pstree` mình có thấy một tiến trình lạ `oneetx.exe` có chạy và đang mở một tiến trình con `rundll32.exe`, đây là chương trình duy nhất gọi tới `rundll32.exe`. 

![image](https://hackmd.io/_uploads/HkjPzl3tWg.png)

Tra cứu thêm về `oneetx.exe` thì mình nhận thấy đây chính là malware [ANY.RUN-report](https://any.run/report/28f5e5e43a67a48c6a41f9814a50b6faf5d20dfee6b17e867429efca82394681/cc976c28-df2a-4875-9a7d-13425eca71ba)
![image](https://hackmd.io/_uploads/BJI1IenF-x.png)

> Flag: oneetx.exe
---
### Q2 What is the child process name of the suspicious process?

Dựa vào thông tin khi chạy `volatility3` với plugin `windows.pstree` mình thấy rằng `oneetx.exe` đang gọi tới `rundll32.exe`, ký hiệu child process thể hiện qua dấu `*`.

![image](https://hackmd.io/_uploads/BydW8g3t-g.png)

> Flag: rundll32.exe

---
### Q3 What is the memory protection applied to the suspicious process memory region?

![image](https://hackmd.io/_uploads/HybjcgnFWl.png)

`vol -f ~/Desktop/106-RedLine/temp_extract_dir/MemoryDump.mem windows.vadinfo --pid 5896`

:::spoiler Result
``` rust!
Volatility 3 Framework 2.28.0
Progress:  100.00               PDB scanning finished                        
PID     Process Offset  Start VPN       End VPN Tag     Protection      CommitCharge    PrivateMemory   Parent  File    File output

5896    oneetx.exe      0xffffad818ddb2c40      0x73da0000      0x74024fff      Vad     PAGE_EXECUTE_WRITECOPY  554     0       0x0     \Windows\SysWOW64\AcLayers.dll  Disabled
5896    oneetx.exe      0xffffad818ddc5200      0x1a60000       0x2e60fff       Vad     PAGE_READONLY   0       0       0xffffad818ddb2c40      N/A     Disabled
5896    oneetx.exe      0xffffad818d6d5b70      0x1390000       0x139ffff       VadS    PAGE_READWRITE  10      1       0xffffad818ddc5200      N/A     Disabled
5896    oneetx.exe      0xffffad818d6bc2b0      0x1000000       0x11fffff       VadS    PAGE_READWRITE  11      1       0xffffad818d6d5b70      N/A     Disabled
5896    oneetx.exe      0xffffad818ddab1c0      0xfc0000        0xfc0fff        Vad     PAGE_READONLY   0       0       0xffffad818d6bc2b0      N/A     Disabled
5896    oneetx.exe      0xffffad818d2c7ac0      0xec0000        0xfb7fff        Vad     PAGE_EXECUTE_WRITECOPY  0       0       0xffffad818ddab1c0      \Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe      Disabled
5896    oneetx.exe      0xffffad818d6d5940      0x400000        0x437fff        VadS    PAGE_EXECUTE_READWRITE  56      1       0xffffad818d2c7ac0      N/A     Disabled
5896    oneetx.exe      0xffffad818ddade20      0xfe0000        0xfe0fff        Vad     PAGE_READONLY   0       0       0xffffad818ddab1c0      N/A     Disabled
5896    oneetx.exe      0xffffad818ddab940      0xfd0000        0xfd0fff        Vad     PAGE_READONLY   0       0       0xffffad818ddade20      N/A     Disabled
5896    oneetx.exe      0xffffad81876f1b30      0xff0000        0xff3fff        Vad     PAGE_READONLY   0       0       0xffffad818ddade20      N/A     Disabled
5896    oneetx.exe      0xffffad818d6cb940      0x1360000       0x1361fff       VadS    PAGE_READWRITE  2       1       0xffffad818d6bc2b0      N/A     Disabled
5896    oneetx.exe      0xffffad818d6c5cc0      0x1220000       0x125ffff       VadS    PAGE_READWRITE  11      1       0xffffad818d6cb940      N/A     Disabled
5896    oneetx.exe      0xffffad818d2cfea0      0x1200000       0x121cfff       Vad     PAGE_READONLY   0       0       0xffffad818d6c5cc0      N/A     Disabled
5896    oneetx.exe      0xffffad818d6c8a10      0x1260000       0x135ffff       VadS    PAGE_READWRITE  6       1       0xffffad818d6c5cc0      N/A     Disabled
5896    oneetx.exe      0xffffad818ddac840      0x1370000       0x1370fff       Vad     PAGE_READONLY   0       0       0xffffad818d6cb940      N/A     Disabled
5896    oneetx.exe      0xffffad818ddae780      0x1380000       0x1380fff       Vad     PAGE_READONLY   0       0       0xffffad818ddac840      N/A     Disabled
5896    oneetx.exe      0xffffad818d6d5c60      0x1510000       0x160ffff       VadS    PAGE_READWRITE  218     1       0xffffad818d6d5b70      N/A     Disabled
5896    oneetx.exe      0xffffad818f029ce0      0x1490000       0x149dfff       VadS    PAGE_READWRITE  2       1       0xffffad818d6d5c60      N/A     Disabled
5896    oneetx.exe      0xffffad818ddaf860      0x13b0000       0x13bffff       Vad     PAGE_READWRITE  0       0       0xffffad818f029ce0      N/A     Disabled
5896    oneetx.exe      0xffffad818ddaebe0      0x13a0000       0x13a0fff       Vad     PAGE_READONLY   0       0       0xffffad818ddaf860      N/A     Disabled
5896    oneetx.exe      0xffffad818ddb24c0      0x13c0000       0x1488fff       Vad     PAGE_READONLY   0       0       0xffffad818ddaf860      \Windows\System32\locale.nls    Disabled
5896    oneetx.exe      0xffffad818e502260      0x14b0000       0x14b7fff       Vad     PAGE_READONLY   0       0       0xffffad818f029ce0      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc3ea0      0x14a0000       0x14a2fff       Vad     PAGE_EXECUTE_WRITECOPY  0       0       0xffffad818e502260      \Windows\SysWOW64\sfc.dll       Disabled
5896    oneetx.exe      0xffffad818ddc62e0      0x1500000       0x1500fff       Vad     PAGE_READWRITE  0       0       0xffffad818e502260      N/A     Disabled
5896    oneetx.exe      0xffffad818c29eaf0      0x14c0000       0x14fffff       VadS    PAGE_READWRITE  11      1       0xffffad818ddc62e0      N/A     Disabled
5896    oneetx.exe      0xffffad818f029600      0x16c0000       0x16cffff       VadS    PAGE_READWRITE  7       1       0xffffad818d6d5c60      N/A     Disabled
5896    oneetx.exe      0xffffad818f02f6e0      0x1690000       0x1696fff       VadS    PAGE_READWRITE  1       1       0xffffad818f029600      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc5d40      0x16b0000       0x16b0fff       Vad     PAGE_READONLY   0       0       0xffffad818f02f6e0      N/A     Disabled
5896    oneetx.exe      0xffffad818e503480      0x16d0000       0x18cffff       Vad     PAGE_READONLY   0       0       0xffffad818f029600      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc5160      0x18d0000       0x1a50fff       Vad     PAGE_READONLY   0       0       0xffffad818e503480      N/A     Disabled
5896    oneetx.exe      0xffffad818f035e50      0x3f00000       0x3f00fff       VadS    PAGE_READWRITE  1       1       0xffffad818ddc5200      N/A     Disabled
5896    oneetx.exe      0xffffad818f02a190      0x3770000       0x377ffff       VadS    PAGE_READWRITE  1       1       0xffffad818f035e50      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc7460      0x35f0000       0x35f6fff       Vad     PAGE_READONLY   0       0       0xffffad818f02a190      \Windows\Registration\R000000000006.clb Disabled
5896    oneetx.exe      0xffffad818ddc4260      0x3170000       0x34a7fff       Vad     PAGE_READONLY   0       0       0xffffad818ddc7460      N/A     Disabled
5896    oneetx.exe      0xffffad818c2a02b0      0x2e70000       0x2f6ffff       VadS    PAGE_READWRITE  4       1       0xffffad8190ac5480      N/A     Disabled
5896    oneetx.exe      0xffffad818d6c4c30      0x34b0000       0x34effff       VadS    PAGE_READWRITE  11      1       0xffffad818ddc4260      N/A     Disabled
5896    oneetx.exe      0xffffad818d6cd150      0x34f0000       0x35effff       VadS    PAGE_READWRITE  5       1       0xffffad818d6c4c30      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc7a00      0x3750000       0x3753fff       Vad     PAGE_READONLY   0       0       0xffffad818ddc7460      \ProgramData\Microsoft\Windows\Caches\cversions.2.dbDisabled
5896    oneetx.exe      0xffffad818f02b310      0x3600000       0x360ffff       VadS    PAGE_NOACCESS   1       1       0xffffad818ddc7a00      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc75a0      0x3760000       0x3763fff       Vad     PAGE_READONLY   0       0       0xffffad818ddc7a00      \ProgramData\Microsoft\Windows\Caches\cversions.2.dbDisabled
5896    oneetx.exe      0xffffad818ddc7640      0x39b0000       0x39bffff       Vad     PAGE_READONLY   0       0       0xffffad818f02a190      \Windows\System32\en-GB\propsys.dll.mui Disabled
5896    oneetx.exe      0xffffad818ddc7500      0x38c0000       0x3908fff       Vad     PAGE_READONLY   0       0       0xffffad818ddc7640      翀ß챓̠
                                                                                                                                                     쀀དᵓ큌㱐   Disabled
5896    oneetx.exe      0xffffad818ddc6c40      0x3910000       0x39abfff       Vad     PAGE_READONLY   0       0       0xffffad818ddc7500      \ProgramData\Microsoft\Windows\Caches\{DDF571F2-BE98-426D-8288-1A9A39C3FDA2}.2.ver0x0000000000000001.db     Disabled
5896    oneetx.exe      0xffffad818ddc7b40      0x39d0000       0x39e9fff       Vad     PAGE_READONLY   0       0       0xffffad818ddc7640      \Users\Tammam\AppData\Local\Microsoft\Windows\Caches\{AFBF9F1A-8EE8-4C77-AF34-C647E37CA0D9}.1.ver0x0000000000000001.db      Disabled
5896    oneetx.exe      0xffffad818ddcfd40      0x39c0000       0x39c0fff       Vad     PAGE_READWRITE  0       0       0xffffad818ddc7b40      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc8f40      0x39f0000       0x39f0fff       Vad     PAGE_READWRITE  0       0       0xffffad818ddc7b40      N/A     Disabled
5896    oneetx.exe      0xffffad818ddd4160      0x4090000       0x4090fff       Vad     PAGE_READONLY   0       0       0xffffad818f035e50      N/A     Disabled
5896    oneetx.exe      0xffffad818ddd29a0      0x4070000       0x4070fff       Vad     PAGE_READONLY   0       0       0xffffad818ddd4160      N/A     Disabled
5896    oneetx.exe      0xffffad818f035ea0      0x3f10000       0x3f10fff       VadS    PAGE_READWRITE  1       1       0xffffad818ddd29a0      N/A     Disabled
5896    oneetx.exe      0xffffad818ddae140      0x4060000       0x4060fff       Vad     PAGE_READWRITE  0       0       0xffffad818f035ea0      N/A     Disabled
5896    oneetx.exe      0xffffad818ddd3c60      0x4080000       0x408ffff       Vad     PAGE_READONLY   0       0       0xffffad818ddd29a0      N/A     Disabled
5896    oneetx.exe      0xffffad8189d257b0      0x4220000       0x4223fff       Vad     PAGE_READONLY   0       0       0xffffad818ddd4160      \ProgramData\Microsoft\Windows\Caches\cversions.2.dbDisabled
5896    oneetx.exe      0xffffad818ddd4340      0x40b0000       0x40b2fff       Vad     PAGE_READONLY   0       0       0xffffad8189d257b0      \Windows\System32\en-US\mswsock.dll.mui Disabled
5896    oneetx.exe      0xffffad818ddd34e0      0x40a0000       0x40a0fff       Vad     PAGE_READWRITE  0       0       0xffffad818ddd4340      N/A     Disabled
5896    oneetx.exe      0xffffad818ddd3940      0x40c0000       0x40d0fff       Vad     PAGE_READONLY   0       0       0xffffad818ddd4340      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc46c0      0x73050000      0x730c2fff      Vad     PAGE_EXECUTE_WRITECOPY  4       0       0xffffad8189d257b0      \Windows\SysWOW64\winspool.drv  Disabled
5896    oneetx.exe      0xffffad818ddc43a0      0x6c5a0000      0x6c9f3fff      Vad     PAGE_EXECUTE_WRITECOPY  6       0       0xffffad818ddc46c0      菨ル護Ǚ菨ル護Ǚ菨ル護Ǚ菨ル護Ǚ    Disabled
5896    oneetx.exe      0xffffad818ddae460      0x76390000      0x7647ffff      Vad     PAGE_EXECUTE_WRITECOPY  5       0       0xffffad818ddb2c40      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc4b20      0x754e0000      0x754eefff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddae460      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc7820      0x750c0000      0x750d7fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddc4b20      \Windows\SysWOW64\profapi.dll   Disabled
5896    oneetx.exe      0xffffad818ddd1a00      0x74bb0000      0x74be1fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddc7820      \Windows\SysWOW64\IPHLPAPI.DLL  Disabled
5896    oneetx.exe      0xffffad818ddd01a0      0x74550000      0x74561fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddd1a00      \Windows\SysWOW64\OnDemandConnRouteHelper.dll       Disabled
5896    oneetx.exe      0xffffad818ddc5a20      0x743b0000      0x74471fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddd01a0      \Windows\SysWOW64\propsys.dll   Disabled
5896    oneetx.exe      0xffffad818ddcdae0      0x740e0000      0x74287fff      Vad     PAGE_EXECUTE_WRITECOPY  14      0       0xffffad818ddc5a20      \Windows\SysWOW64\urlmon.dll    Disabled
5896    oneetx.exe      0xffffad818ddd1960      0x74490000      0x744e1fff      Vad     PAGE_EXECUTE_WRITECOPY  4       0       0xffffad818ddc5a20      \Windows\SysWOW64\mswsock.dll   Disabled
5896    oneetx.exe      0xffffad818ddd0240      0x74a50000      0x74b18fff      Vad     PAGE_EXECUTE_WRITECOPY  4       0       0xffffad818ddd01a0      \Windows\SysWOW64\winhttp.dll   Disabled
5896    oneetx.exe      0xffffad818ddce580      0x74e30000      0x74e50fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddd1a00      1.1.mum Disabled
5896    oneetx.exe      0xffffad818ddcdcc0      0x74e90000      0x750bcfff      Vad     PAGE_EXECUTE_WRITECOPY  10      0       0xffffad818ddce580      \Windows\SysWOW64\iertutil.dll  Disabled
5896    oneetx.exe      0xffffad818ddcbf60      0x752d0000      0x752eafff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddc7820      \Windows\SysWOW64\edputil.dll   Disabled
5896    oneetx.exe      0xffffad818ddccf00      0x751f0000      0x7520cfff      Vad     PAGE_EXECUTE_WRITECOPY  11      0       0xffffad818ddcbf60      \Windows\SysWOW64\srvcli.dll    Disabled
5896    oneetx.exe      0xffffad818ddce940      0x751e0000      0x751eafff      Vad     PAGE_EXECUTE_WRITECOPY  2       0       0xffffad818ddccf00      \Windows\SysWOW64\netutils.dll  Disabled
5896    oneetx.exe      0xffffad818ddd2040      0x752f0000      0x752f7fff      Vad     PAGE_EXECUTE_WRITECOPY  2       0       0xffffad818ddcbf60      \Windows\SysWOW64\winnsi.dll    Disabled
5896    oneetx.exe      0xffffad818ddbe9a0      0x76090000      0x76125fff      Vad     PAGE_EXECUTE_WRITECOPY  4       0       0xffffad818ddc4b20      N/A     Disabled
5896    oneetx.exe      0xffffad818ddb3b40      0x75b50000      0x75beefff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddbe9a0      \Windows\SysWOW64\apphelp.dll   Disabled
5896    oneetx.exe      0xffffad818ddc57a0      0x75510000      0x75536fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddb3b40      \Windows\SysWOW64\wldp.dll      Disabled
5896    oneetx.exe      0xffffad818ddc2f00      0x754f0000      0x75508fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddc57a0      \Windows\SysWOW64\mpr.dll       Disabled
5896    oneetx.exe      0xffffad818ddc66a0      0x75540000      0x75b4cfff      Vad     PAGE_EXECUTE_WRITECOPY  9       0       0xffffad818ddc57a0      \Windows\SysWOW64\windows.storage.dll   Disabled
5896    oneetx.exe      0xffffad818ddb4180      0x75d90000      0x75e4efff      Vad     PAGE_EXECUTE_WRITECOPY  7       0       0xffffad818ddb3b40      \Windows\SysWOW64\msvcrt.dll    Disabled
5896    oneetx.exe      0xffffad818ddc5980      0x75ca0000      0x75caefff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddb4180      㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀㙎倀    Disabled
5896    oneetx.exe      0xffffad818ddac700      0x75c20000      0x75c93fff      Vad     PAGE_EXECUTE_WRITECOPY  5       0       0xffffad818ddc5980      \Windows\SysWOW64\uxtheme.dll   Disabled
5896    oneetx.exe      0xffffad818ddb56c0      0x75cb0000      0x75d2afff      Vad     PAGE_EXECUTE_WRITECOPY  5       0       0xffffad818ddc5980      \Windows\SysWOW64\msvcp_win.dll Disabled
5896    oneetx.exe      0xffffad818ddc4d00      0x75eb0000      0x75f0efff      Vad     PAGE_EXECUTE_WRITECOPY  2       0       0xffffad818ddb4180      \Windows\SysWOW64\bcryptprimitives.dll  Disabled
5896    oneetx.exe      0xffffad818ddd2860      0x75f10000      0x75f16fff      Vad     PAGE_EXECUTE_WRITECOPY  2       0       0xffffad818ddc4d00      \Windows\SysWOW64\nsi.dll       Disabled
5896    oneetx.exe      0xffffad818ddc6380      0x76220000      0x7629dfff      Vad     PAGE_EXECUTE_WRITECOPY  6       0       0xffffad818ddbe9a0      \Windows\SysWOW64\clbcatq.dll   Disabled
5896    oneetx.exe      0xffffad818ddc5660      0x76130000      0x76212fff      Vad     PAGE_EXECUTE_WRITECOPY  4       0       0xffffad818ddc6380      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc5520      0x762a0000      0x7631afff      Vad     PAGE_EXECUTE_WRITECOPY  6       0       0xffffad818ddc6380      \Windows\SysWOW64\advapi32.dll  Disabled
5896    oneetx.exe      0xffffad818ddc4a80      0x76320000      0x76382fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddc5520      \Windows\SysWOW64\ws2_32.dll    Disabled
5896    oneetx.exe      0xffffad818d2ca2c0      0x77de0000      0x77f83fff      Vad     PAGE_EXECUTE_WRITECOPY  9       0       0xffffad818ddae460      \Windows\SysWOW64\ntdll.dll     Disabled
5896    oneetx.exe      0xffffad818ddb62a0      0x77620000      0x777bafff      Vad     PAGE_EXECUTE_WRITECOPY  8       0       0xffffad818d2ca2c0      \Windows\SysWOW64\user32.dll    Disabled
5896    oneetx.exe      0xffffad818ddbe540      0x76d00000      0x76d44fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddb62a0      \Windows\SysWOW64\shlwapi.dll   Disabled
5896    oneetx.exe      0xffffad818ddadf60      0x76a50000      0x76c68fff      Vad     PAGE_EXECUTE_WRITECOPY  6       0       0xffffad818ddbe540      \Windows\SysWOW64\KernelBase.dll        Disabled
5896    oneetx.exe      0xffffad818ddbf760      0x76610000      0x76a48fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddadf60      \Windows\SysWOW64\setupapi.dll  Disabled
5896    oneetx.exe      0xffffad818ddc4bc0      0x76c70000      0x76ce5fff      Vad     PAGE_EXECUTE_WRITECOPY  5       0       0xffffad818ddadf60      \Windows\SysWOW64\sechost.dll   Disabled
5896    oneetx.exe      0xffffad818ddb54e0      0x773f0000      0x774ccfff      Vad     PAGE_EXECUTE_WRITECOPY  5       0       0xffffad818ddbe540      \Windows\SysWOW64\gdi32full.dll Disabled
5896    oneetx.exe      0xffffad818ddb7920      0x76e30000      0x773e4fff      Vad     PAGE_EXECUTE_WRITECOPY  11      0       0xffffad818ddb54e0      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc4440      0x76da0000      0x76e26fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddb7920      N/A     Disabled
5896    oneetx.exe      0xffffad818ddb5800      0x774d0000      0x775effff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddb54e0      \Windows\SysWOW64\ucrtbase.dll  Disabled
5896    oneetx.exe      0xffffad818ddc5480      0x775f0000      0x77614fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddb5800      \Windows\SysWOW64\imm32.dll     Disabled
5896    oneetx.exe      0xffffad818ddb65c0      0x77c90000      0x77ca7fff      Vad     PAGE_EXECUTE_WRITECOPY  2       0       0xffffad818ddb62a0      \Windows\SysWOW64\win32u.dll    Disabled
5896    oneetx.exe      0xffffad818ddbeea0      0x77900000      0x77b7ffff      Vad     PAGE_EXECUTE_WRITECOPY  6       0       0xffffad818ddb65c0      \Windows\SysWOW64\combase.dll   Disabled
5896    oneetx.exe      0xffffad818ddc12e0      0x777c0000      0x777fafff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddbeea0      \Windows\SysWOW64\cfgmgr32.dll  Disabled
5896    oneetx.exe      0xffffad818ddb5da0      0x77c60000      0x77c82fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddbeea0      N/A     Disabled
5896    oneetx.exe      0xffffad818ddc2e60      0x77b80000      0x77b98fff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddb5da0      \Windows\SysWOW64\bcrypt.dll    Disabled
5896    oneetx.exe      0xffffad818ddacca0      0x77dd0000      0x77dd9fff      Vad     PAGE_EXECUTE_WRITECOPY  2       0       0xffffad818ddb65c0      \Windows\System32\wow64cpu.dll  Disabled
5896    oneetx.exe      0xffffad818ddc0020      0x77cb0000      0x77d6dfff      Vad     PAGE_EXECUTE_WRITECOPY  3       0       0xffffad818ddacca0      \Windows\SysWOW64\rpcrt4.dll    Disabled
5896    oneetx.exe      0xffffad818d6b9290      0x7ffed000      0x7ffedfff      VadS    PAGE_READONLY   1       1       0xffffad818d2ca2c0      N/A     Disabled
5896    oneetx.exe      0xffffad818d6d5990      0x7fb20000      0x7fb21fff      VadS    PAGE_READWRITE  1       1       0xffffad818d6b9290      N/A     Disabled
5896    oneetx.exe      0xffffad818d6bfb90      0x7faf0000      0x7faf1fff      VadS    PAGE_READWRITE  1       1       0xffffad818d6d5990      N/A     Disabled
5896    oneetx.exe      0xffffad818ddb2100      0x7f9e0000      0x7fadffff      Vad     PAGE_READONLY   0       0       0xffffad818d6bfb90      N/A     Disabled
5896    oneetx.exe      0xffffad818d6d56c0      0x7fae0000      0x7fae8fff      VadS    PAGE_READWRITE  1       1       0xffffad818ddb2100      N/A     Disabled
5896    oneetx.exe      0xffffad818d6d5b20      0x7fb00000      0x7fb10fff      VadS    PAGE_READWRITE  1       1       0xffffad818d6bfb90      N/A     Disabled
5896    oneetx.exe      0xffffad818d2ce780      0x7fb40000      0x7fb62fff      Vad     PAGE_READONLY   0       0       0xffffad818d6d5990      N/A     Disabled
5896    oneetx.exe      0xffffad818d2cde20      0x7fb30000      0x7fb30fff      Vad     PAGE_READONLY   0       0       0xffffad818d2ce780      N/A     Disabled
5896    oneetx.exe      0xffffad818d6b6ea0      0x7ffe0000      0x7ffe0fff      VadS    PAGE_READONLY   1       1       0xffffad818d2ce780      N/A     Disabled
5896    oneetx.exe      0xffffad818ddacde0      0x7ffa69860000  0x7ffa698b8fff  Vad     PAGE_EXECUTE_WRITECOPY  5       0       0xffffad818d6b9290      \Windows\System32\wow64.dll     Disabled
5896    oneetx.exe      0xffffad818d6baeb0      0x7fff0000      0xffffffff      VadS    PAGE_READONLY   2147483647      1       0xffffad818ddacde0      N/A     Disabled
5896    oneetx.exe      0xffffad818ddacac0      0x7ffa68810000  0x7ffa68892fff  Vad     PAGE_EXECUTE_WRITECOPY  5       0       0xffffad818d6baeb0      蕵遡驐鹇鵉顐鑕陌陇顀騻鰺鸽齃G   Disabled
5896    oneetx.exe      0xffffad818d2c7f20      0x7ffa69c70000  0x7ffa69e67fff  Vad     PAGE_EXECUTE_WRITECOPY  16      0       0xffffad818ddacde0      \Windows\System32\ntdll.dll     Disabled
```
:::

Mình thấy rằng `oneetx.exe` đã dùng các hàm `PAGE_EXECUTE_WRITECOPY`, `PAGE_EXECUTE_READWRITE`, `PAGE_READWRITE`, `PAGE_READONLY`, `PAGE_NOACCESS` để bảo vệ bộ nhớ giúp malware thực thi.
Trong đó `PAGE_EXECUTE_WRITECOPY` được dùng nhiều hơn cả.

![image](https://hackmd.io/_uploads/HyS46lhK-g.png)

Ngắn gọn về hành vi của oneetx.exe:

1.  Lạm dụng Copy-on-Write (COW): Nó yêu cầu quyền `PAGE_EXECUTE_WRITECOPY` để Windows tạo một bản sao riêng của các DLL hệ thống (`ntdll.dll`, `sechost.dll`...) vào bộ nhớ của nó.
2.  Sửa đổi trong RAM (Patching): Nó chỉnh sửa mã lệnh (code) trên bản sao này để thay đổi cách các hàm hệ thống hoạt động (ví dụ: bẻ lái hàm kiểm tra mật khẩu hoặc ghi log).
3.  Tàng hình: Vì nó chỉ sửa bản sao trong RAM, các file DLL gốc trên ổ cứng vẫn "sạch", giúp nó qua mặt các trình quét virus truyền thống.
4.  Dấu hiệu độc hại: Việc có các vùng nhớ thực thi nhưng không có file gốc (N/A) và tên file chứa ký tự lạ khẳng định đây là mã độc đang thực hiện chỉnh sửa bộ nhớ để chiếm quyền điều khiển.


> Flag: PAGE_EXECUTE_WRITECOPY

---
### Q4 What is the name of the process responsible for the VPN connection?

Ở đây đẻ tìm ứng dụng dụng thực hiện kết nối VPN mình dùng tool với plugin `netscan` nhưng không tìm được ứng dụng nào có liên quan tới VPN. Mình dùng `pslist` để list ra tất cả tiến trình đang chạy lúc đó để xem có ứng dụng nào liên quan tới VPN hay không.

![image](https://hackmd.io/_uploads/Hyppl-ntbl.png)

Phần lơn các úng dụng thông thường đều đang chạy nền nên chỉ có thời gian tạo chứ không thấy thòi gian kết thúc. Vậy nên mình sẽ tập trung vào những ứng dụng có thời gian kết thúc để lọc thêm.

![image](https://hackmd.io/_uploads/HJh_LbhK-l.png)

Kết quả là mình lọc ra được ứng dụng VPN là `Outline.exe` [Link](https://getoutline.org/)

![image](https://hackmd.io/_uploads/S1G1DW2Y-e.png)

> Flag: Outline.exe

---
### Q5 What is the attacker's IP address?

Khi biết được tên ứng dụng VPN mình quay lại check `pstree` xem ứng dụng này có liên quan tới ứng dụng nào khác không. Kết quả thu được là `Outline` là tiến trình cha của `tun2socks.exe` - là một thành phần phần mềm (thường đi kèm với ứng dụng VPN/Proxy) dùng để chuyển đổi lưu lượng mạng từ giao diện ảo (TUN) thành các kết nối SOCKS proxy. Nó giúp "socksify"([SOCKS5](https://mona.media/socks5-la-gi/)) toàn bộ lưu lượng TCP/UDP của hệ thống hoặc ứng dụng, ép buộc chúng đi qua proxy SOCKS để ẩn danh, vượt tường lửa hoặc bảo mật dữ liệu.

![image](https://hackmd.io/_uploads/ryCCwWhtZg.png)

![image](https://hackmd.io/_uploads/By8tubnYWe.png)

Mình dùng `netscan` để quét các hoạt động mạng liên quan tới `tun2socks.exe`

![image](https://hackmd.io/_uploads/ryIB9-nFZe.png)

Kết quả mình thấy app đang kết nối tới IP `38.121.43.65`

> Flag: `38.121.43.65`

---
### Q6 What is the full URL of the PHP file that the attacker visited?

Để trích xuất ra được url trong file memory dump mình dùng `strings` để trích ra các dòng text format ASCII, rồi grep ra những url có liên quan.

![image](https://hackmd.io/_uploads/B1M6Xf3Fbe.png)

` cat strings-ou.txt| grep http | grep php `

![image](https://hackmd.io/_uploads/SJtUmznKZg.png)

> Flag: `http://77.91.124.20/store/games/index.php`

---
### Q7 What is the full path of the malicious executable?

Mình đã biết tên file malware là `oneetx.exe` nên mình sẽ dùng plugin `filescan` để tìm ra đường dẫn nơi lưu trữ của nó.

![image](https://hackmd.io/_uploads/SJ7YSzhtZg.png)

> Flag: `C:\Users\Tammam\AppData\Local\Temp\c3912af058\oneetx.exe`