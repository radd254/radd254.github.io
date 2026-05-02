---
title: '[Level-2]-Ramnit'
date: 2026-03-08

---

# Lab Report - Ramnit
**DatHN5 - SO3 - FSAS**
---

Analyze a memory dump using Volatility to identify a malicious process, extract network IOCs, file hash, and compilation timestamp, correlating with external threat intelligence.

Category:
Endpoint Forensics

Tactics:
Execution, Defense Evasion,Command and Control

Tools:
Volatility 3, VirusTotal


### Scenario

Our intrusion detection system has alerted us to suspicious behavior on a workstation, pointing to a likely malware intrusion. A memory dump of this system has been taken for analysis. Your task is to analyze this dump, trace the malware’s actions, and report key findings.

## Write up

Tình huống là hệ thống IDS phát hiện ra hành vi khả nghi trên một máy trạm, giống như là hành vi của một malware. Nhiệm vụ của ta là phân tích memory dump từ máy trạm kia để phân tích ra các hành vi của malware như các IOCs về hoạt động mạng, những file mã độc được sửa dụng, các timeline có liên quan.

Ta được cấp một file memory dump, trước hết mình sẽ xem thông tin cơ bản qua lệnh `file`, kết quả cho ra đây là memory dump từ máy Windows bản 64-bit

![image](https://hackmd.io/_uploads/Bk_V_GVY-l.png)


### **Q1:What is the name of the process responsible for the suspicious activity?**

`vol -f ~/Desktop/159-Ramnit/memory.dmp windows.pstree | grep .exe`
:::spoiler Result
```rust
* 320ess4  100.0smss.exe        0xca82b1a95040  2       -       N/A     False   2024-02-01 19:48:22.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\smss.exe       \SystemRoot\System32\smss.exe   \SystemRoot\System32\smss.exe
448     440     csrss.exe       0xca82b1f68080  11      -       0       False   2024-02-01 19:48:23.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\csrss.exe      %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16        C:\Windows\system32\csrss.exe
524     440     wininit.exe     0xca82b2843080  2       -       0       False   2024-02-01 19:48:23.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\wininit.exe    wininit.exe     C:\Windows\system32\wininit.exe
* 676   524     lsass.exe       0xca82b2923080  10      -       0       False   2024-02-01 19:48:23.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\lsass.exe      C:\Windows\system32\lsass.exe   C:\Windows\system32\lsass.exe
* 660   524     services.exe    0xca82b28e9080  8       -       0       False   2024-02-01 19:48:23.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\services.exe   C:\Windows\system32\services.exe        C:\Windows\system32\services.exe
** 2564 660     spoolsv.exe     0xca82b3c5b200  8       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\spoolsv.exe    C:\Windows\System32\spoolsv.exe C:\Windows\System32\spoolsv.exe
** 5132 660     svchost.exe     0xca82b7752280  9       -       0       False   2024-02-01 19:48:28.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc        C:\Windows\system32\svchost.exe
** 3104 660     svchost.exe     0xca82b7229080  12      -       0       False   2024-02-01 19:48:26.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalService -p -s CDPSvcC:\Windows\system32\svchost.exe
** 1068 660     svchost.exe     0xca82b3115300  5       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s lmhosts      C:\Windows\System32\svchost.exe
** 2092 660     svchost.exe     0xca82b0f38080  13      -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p C:\Windows\System32\svchost.exe
*** 7272        2092    audiodg.exe     0xca82b8308080  5       -       0       False   2024-02-01 19:48:49.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\audiodg.exe    C:\Windows\system32\AUDIODG.EXE 0x4b8   C:\Windows\system32\AUDIODG.EXE
** 2612 660     svchost.exe     0xca82b3ca22c0  5       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalService -p      C:\Windows\system32\svchost.exe
** 3128 660     svchost.exe     0xca82b3e6b080  7       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s LanmanServer       C:\Windows\system32\svchost.exe
** 3160 660     svchost.exe     0xca82b3e9f2c0  2       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalService -p -s SstpSvc       C:\Windows\system32\svchost.exe
** 5220 660     svchost.exe     0xca82b77792c0  5       -       1       False   2024-02-01 19:48:28.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc  C:\Windows\system32\svchost.exe
** 1644 660     svchost.exe     0xca82b38c7300  3       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalService -p -s DispBrokerDesktopSvc  C:\Windows\system32\svchost.exe
** 3692 660     svchost.exe     0xca82b7061280  6       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TabletInputService    C:\Windows\System32\svchost.exe
*** 3936        3692    ctfmon.exe      0xca82b7107240  11      -       1       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\ctfmon.exe     "ctfmon.exe"    C:\Windows\system32\ctfmon.exe
** 6252 660     SearchIndexer.  0xca82b7daa0c0  16      -       0       False   2024-02-01 19:48:30.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\SearchIndexer.exe      C:\Windows\system32\SearchIndexer.exe /Embedding   C:\Windows\system32\SearchIndexer.exe
*** 8696        6252    SearchProtocol  0xca82b8c08300  9       -       0       False   2024-02-01 19:53:28.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\SearchProtocolHost.exe "C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe2_ Global\UsGthrCtrlFltPipeMssGthrPipe2 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon"     C:\Windows\system32\SearchProtocolHost.exe
*** 3004        6252    SearchFilterHo  0xca82b1c74300  4       -       0       False   2024-02-01 19:53:28.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\SearchFilterHost.exe   "C:\Windows\system32\SearchFilterHost.exe" 0 812 816 824 8192 820 796       C:\Windows\system32\SearchFilterHost.exe
** 1136 660     svchost.exe     0xca82b313e300  8       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog     C:\Windows\System32\svchost.exe
** 1144 660     svchost.exe     0xca82b313f300  12      -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule  C:\Windows\system32\svchost.exe
*** 3152        1144    taskhostw.exe   0xca82b7681280  7       -       1       False   2024-02-01 19:48:27.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\taskhostw.exe  taskhostw.exe   C:\Windows\system32\taskhostw.exe
*** 3116        1144    taskhostw.exe   0xca82b3e6a300  8       -       1       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\taskhostw.exe  taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}C:\Windows\system32\taskhostw.exe
*** 7500        1144    MicrosoftEdgeU  0xca82b79e5080  3       -       0       True    2024-02-01 19:51:24.000000 UTC  N/A     \Device\HarddiskVolume3\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe        "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c    C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe
** 1156 660     svchost.exe     0xca82b3140080  5       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s ProfSvc   C:\Windows\system32\svchost.exe
** 3208 660     svchost.exe     0xca82b3ed6280  3       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TrkWks        C:\Windows\System32\svchost.exe
** 1164 660     svchost.exe     0xca82b3153280  3       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService    C:\Windows\System32\svchost.exe
** 2704 660     svchost.exe     0xca82b3cbb300  5       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k NetworkService -p -s LanmanWorkstation   C:\Windows\System32\svchost.exe
** 1172 660     svchost.exe     0xca82b3152080  4       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s TimeBrokerSvc        C:\Windows\system32\svchost.exe
** 1684 660     svchost.exe     0xca82b390c300  5       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k NetworkService -p -s NlaSvc      C:\Windows\System32\svchost.exe
** 4760 660     svchost.exe     0xca82b7757280  4       -       0       False   2024-02-01 19:48:28.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s WdiSystemHost C:\Windows\System32\svchost.exe
** 3228 660     svchost.exe     0xca82b7682080  3       -       0       False   2024-02-01 19:48:28.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k wsappx -p -s ClipSVC C:\Windows\System32\svchost.exe
** 3248 660     VGAuthService.  0xca82b3edd300  3       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe       "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"      C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe
** 4276 660     dllhost.exe     0xca82b7320280  15      -       0       False   2024-02-01 19:48:26.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\dllhost.exe    C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}   C:\Windows\system32\dllhost.exe
** 1716 660     svchost.exe     0xca82b39042c0  5       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalService -p -s EventSystem   C:\Windows\system32\svchost.exe
** 3256 660     vm3dservice.ex  0xca82b3edb0c0  5       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\vm3dservice.exe        C:\Windows\system32\vm3dservice.exe     C:\Windows\system32\vm3dservice.exe
*** 3544        3256    vm3dservice.ex  0xca82b3fce200  6       -       1       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\vm3dservice.exe        vm3dservice.exe -n      C:\Windows\system32\vm3dservice.exe
** 1724 660     svchost.exe     0xca82b3920080  6       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s SysMain       C:\Windows\system32\svchost.exe
** 4796 660     svchost.exe     0xca82b758d300  7       -       0       False   2024-02-01 19:48:26.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -s RmSvc   C:\Windows\System32\svchost.exe
** 2244 660     svchost.exe     0xca82b0e970c0  10      -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k NetworkService -p -s Dnscache    C:\Windows\system32\svchost.exe
** 1740 660     svchost.exe     0xca82b3907080  4       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k netsvcs -p -s Themes C:\Windows\System32\svchost.exe
** 7380 660     svchost.exe     0xca82b79841c0  5       -       0       False   2024-02-01 19:49:00.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s lfsvc  C:\Windows\system32\svchost.exe
** 2776 660     svchost.exe     0xca82b3d1c2c0  7       -       1       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k UnistackSvcGroup -s CDPUserSvc   C:\Windows\system32\svchost.exe
** 3288 660     wlms.exe        0xca82b3ef1240  3       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\wlms\wlms.exe  C:\Windows\system32\wlms\wlms.exe       C:\Windows\system32\wlms\wlms.exe
** 3296 660     vmtoolsd.exe    0xca82b3ef4280  12      -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Program Files\VMware\VMware Tools\vmtoolsd.exe  "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
** 740  660     svchost.exe     0xca82b30c7240  5       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s gpsvc  C:\Windows\system32\svchost.exe
** 4836 660     msdtc.exe       0xca82b75a7280  12      -       0       False   2024-02-01 19:48:26.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\msdtc.exe      C:\Windows\System32\msdtc.exe   C:\Windows\System32\msdtc.exe
** 2280 660     svchost.exe     0xca82b0fc0080  3       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p C:\Windows\System32\svchost.exe
** 1260 660     svchost.exe     0xca82b318f2c0  4       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -pC:\Windows\system32\svchost.exe
** 2288 660     svchost.exe     0xca82b0fbe080  5       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p C:\Windows\system32\svchost.exe
** 3832 660     svchost.exe     0xca82b8b352c0  6       -       1       False   2024-02-01 19:50:05.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k UnistackSvcGroup     C:\Windows\System32\svchost.exe
** 3852 660     svchost.exe     0xca82b1c90240  13      -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k netsvcs      C:\Windows\System32\svchost.exe
** 2328 660     svchost.exe     0xca82b0fb1080  9       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k appmodel -p -s StateRepository   C:\Windows\system32\svchost.exe
** 3356 660     svchost.exe     0xca82b3efa240  8       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s WpnServiceC:\Windows\system32\svchost.exe
** 7968 660     svchost.exe     0xca82b8ba72c0  4       -       0       False   2024-02-01 19:50:05.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s StorSvc       C:\Windows\System32\svchost.exe
** 808  660     svchost.exe     0xca82b299a240  15      -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k DcomLaunch -p        C:\Windows\system32\svchost.exe
*** 4492        808     WmiPrvSE.exe    0xca82b7424280  13      -       0       False   2024-02-01 19:48:26.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\wbem\WmiPrvSE.exe      C:\Windows\system32\wbem\wmiprvse.exe   C:\Windows\system32\wbem\wmiprvse.exe
*** 7948        808     RuntimeBroker.  0xca82b87e5200  3       -       1       False   2024-02-01 19:49:08.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe      C:\Windows\System32\RuntimeBroker.exe -Embedding    C:\Windows\System32\RuntimeBroker.exe
*** 8848        808     RuntimeBroker.  0xca82b8bd5080  1       -       1       False   2024-02-01 19:49:36.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe      C:\Windows\System32\RuntimeBroker.exe -Embedding    C:\Windows\System32\RuntimeBroker.exe
*** 5912        808     WWAHost.exe     0xca82b8b86080  34      -       1       False   2024-02-01 19:49:19.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\WWAHost.exe    "C:\Windows\system32\wwahost.exe" -ServerName:Microsoft.MicrosoftOfficeHub.wwa      C:\Windows\system32\wwahost.exe
*** 8728        808     WinStore.App.e  0xca82b7df4080  11      -       1       False   2024-02-01 19:49:34.000000 UTC  N/A     \Device\HarddiskVolume3\Program Files\WindowsApps\Microsoft.WindowsStore_11910.1002.5.0_x64__8wekyb3d8bbwe\WinStore.App.exe "C:\Program Files\WindowsApps\Microsoft.WindowsStore_11910.1002.5.0_x64__8wekyb3d8bbwe\WinStore.App.exe" -ServerName:App.AppXc75wvwned5vhz4xyxxecvgdjhdkgsdza.mca       C:\Program Files\WindowsApps\Microsoft.WindowsStore_11910.1002.5.0_x64__8wekyb3d8bbwe\WinStore.App.exe
*** 7068        808     RuntimeBroker.  0xca82b81d42c0  7       -       1       False   2024-02-01 19:48:31.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe      C:\Windows\System32\RuntimeBroker.exe -Embedding    C:\Windows\System32\RuntimeBroker.exe
*** 5676        808     StartMenuExper  0xca82b78c4080  12      -       1       False   2024-02-01 19:48:30.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe      "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca    C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe
*** 2220        808     RuntimeBroker.  0xca82b896d340  6       -       1       False   2024-02-01 19:52:27.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe      C:\Windows\System32\RuntimeBroker.exe -Embedding    C:\Windows\System32\RuntimeBroker.exe
*** 2608        808     ShellExperienc  0xca82b880b340  18      -       1       False   2024-02-01 19:52:26.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe    "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca  C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe
*** 6964        808     LockApp.exe     0xca82b7dca080  12      -       1       False   2024-02-01 19:48:31.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe  "C:\Windows\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe" -ServerName:WindowsDefaultLockScreen.AppX7y4nbzq37zn4ks9k7amqjywdat7d3j2z.mca   C:\Windows\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe
*** 4792        808     SkypeApp.exe    0xca82b88020c0  13      -       1       False   2024-02-01 19:49:06.000000 UTC  N/A     \Device\HarddiskVolume3\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\SkypeApp.exe     "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\SkypeApp.exe" -ServerName:App.AppXffn3yxqvgawq9fpmnhy90fr3y01d1t5b.mca   C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\SkypeApp.exe
*** 7484        808     smartscreen.ex  0xca82b82d0340  17      -       1       False   2024-02-01 19:48:41.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\smartscreen.exe        C:\Windows\System32\smartscreen.exe -Embedding      C:\Windows\System32\smartscreen.exe
*** 5948        808     RuntimeBroker.  0xca82b7a9b080  7       -       1       False   2024-02-01 19:48:30.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe      C:\Windows\System32\RuntimeBroker.exe -Embedding    C:\Windows\System32\RuntimeBroker.exe
*** 6216        808     RuntimeBroker.  0xca82b7b14240  15      -       1       False   2024-02-01 19:48:30.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe      C:\Windows\System32\RuntimeBroker.exe -Embedding    C:\Windows\System32\RuntimeBroker.exe
*** 6984        808     WmiPrvSE.exe    0xca82b8046080  7       -       0       False   2024-02-01 19:48:46.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\wbem\WmiPrvSE.exe      C:\Windows\system32\wbem\wmiprvse.exe   C:\Windows\system32\wbem\wmiprvse.exe
*** 7112        808     ApplicationFra  0xca82b8ba2080  3       -       1       False   2024-02-01 19:49:19.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\ApplicationFrameHost.exe       C:\Windows\system32\ApplicationFrameHost.exe -Embedding     C:\Windows\system32\ApplicationFrameHost.exe
*** 2128        808     SearchApp.exe   0xca82b7b10080  35      -       1       False   2024-02-01 19:48:30.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe "C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe
*** 8420        808     dllhost.exe     0xca82b8e7b300  6       -       1       False   2024-02-01 19:49:21.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\dllhost.exe    C:\Windows\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}   C:\Windows\system32\DllHost.exe
*** 2928        808     RuntimeBroker.  0xca82b82d80c0  6       -       1       False   2024-02-01 19:48:32.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe      C:\Windows\System32\RuntimeBroker.exe -Embedding    C:\Windows\System32\RuntimeBroker.exe
*** 5624        808     RuntimeBroker.  0xca82b8b182c0  1       -       1       False   2024-02-01 19:49:19.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\RuntimeBroker.exe      C:\Windows\System32\RuntimeBroker.exe -Embedding    C:\Windows\System32\RuntimeBroker.exe
** 5932 660     svchost.exe     0xca82b7b0a0c0  10      -       0       False   2024-02-01 19:48:30.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s UsoSvc C:\Windows\system32\svchost.exe
** 2864 660     svchost.exe     0xca82b3d432c0  6       -       1       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService       C:\Windows\system32\svchost.exe
** 1844 660     svchost.exe     0xca82b39bb240  3       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s SENS   C:\Windows\system32\svchost.exe
** 2872 660     svchost.exe     0xca82b3e68240  7       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s TokenBrokerC:\Windows\system32\svchost.exe
** 2876 660     svchost.exe     0xca82b3d55240  22      -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s Winmgmt   C:\Windows\system32\svchost.exe
*** 2964        2876    WMIADAP.exe     0xca82b8b0f340  4       -       0       False   2024-02-01 19:52:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\wbem\WMIADAP.exe       wmiadap.exe /F /T /R    \\?\C:\Windows\system32\wbem\WMIADAP.EXE
** 4416 660     svchost.exe     0xca82b7406240  34      -       0       False   2024-02-01 19:48:26.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k wsappx -p -s AppXSvc C:\Windows\system32\svchost.exe
** 2384 660     svchost.exe     0xca82b0f69080  4       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k netsvcs -p -s ShellHWDetection   C:\Windows\System32\svchost.exe
** 3420 660     svchost.exe     0xca82b3f8f2c0  4       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalService -p -s WdiServiceHost        C:\Windows\System32\svchost.exe
** 2912 660     svchost.exe     0xca82b3d8e240  5       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s IKEEXT C:\Windows\system32\svchost.exe
** 6500 660     svchost.exe     0xca82b84cc080  3       -       0       False   2024-02-01 19:48:49.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s Appinfo   C:\Windows\system32\svchost.exe
** 1384 660     svchost.exe     0xca82b38042c0  4       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalService -p -s nsi  C:\Windows\system32\svchost.exe
** 2920 660     svchost.exe     0xca82b3d90300  5       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k NetworkServiceNetworkRestricted -p -s PolicyAgent        C:\Windows\system32\svchost.exe
** 6504 660     svchost.exe     0xca82b7b16240  4       -       0       False   2024-02-01 19:48:30.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc   C:\Windows\system32\svchost.exe
** 1916 660     svchost.exe     0xca82b3a30280  4       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s AudioEndpointBuilder  C:\Windows\System32\svchost.exe
** 7040 660     SgrmBroker.exe  0xca82b8f85340  8       -       0       False   2024-02-01 19:50:26.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\SgrmBroker.exe C:\Windows\system32\SgrmBroker.exe      C:\Windows\system32\SgrmBroker.exe
** 1420 660     svchost.exe     0xca82b3817240  5       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k netsvcs -p -s UserManagerC:\Windows\system32\svchost.exe
*** 2760        1420    sihost.exe      0xca82b3d1a280  11      -       1       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\sihost.exe     sihost.exe      C:\Windows\system32\sihost.exe
** 1932 660     svchost.exe     0xca82b3a322c0  7       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalService -p -s FontCache     C:\Windows\system32\svchost.exe
** 1944 660     svchost.exe     0xca82b3a362c0  8       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalService -p -s netprofm      C:\Windows\System32\svchost.exe
** 2972 660     svchost.exe     0xca82b3dae300  7       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k NetworkService -p -s CryptSvc    C:\Windows\system32\svchost.exe
** 7580 660     SecurityHealth  0xca82b8586240  14      -       0       False   2024-02-01 19:48:41.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\SecurityHealthService.exe      C:\Windows\system32\SecurityHealthService.exe       C:\Windows\system32\SecurityHealthService.exe
** 928  660     svchost.exe     0xca82b29be2c0  7       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k RPCSS -p     C:\Windows\system32\svchost.exe
** 1452 660     svchost.exe     0xca82b3855300  6       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp C:\Windows\system32\svchost.exe
** 2988 660     svchost.exe     0xca82b3dd8240  11      -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k utcsvc -p    C:\Windows\System32\svchost.exe
** 2484 660     svchost.exe     0xca82b3b382c0  17      -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p C:\Windows\system32\svchost.exe
** 2996 660     svchost.exe     0xca82b3dda2c0  15      -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS  C:\Windows\System32\svchost.exe
** 6080 660     svchost.exe     0xca82b742b340  0       -       0       False   2024-02-01 19:51:24.000000 UTC  2024-02-01 19:51:30.000000 UTC  \Device\HarddiskVolume3\Windows\System32\svchost.exe    -       -
** 2500 660     svchost.exe     0xca82b3be80c0  12      -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k NetworkService -p -s DoSvc       C:\Windows\System32\svchost.exe
** 2004 660     svchost.exe     0xca82b3b2c300  3       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s WinHttpAutoProxySvc  C:\Windows\system32\svchost.exe
** 984  660     svchost.exe     0xca82b3038240  5       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k DcomLaunch -p -s LSM C:\Windows\system32\svchost.exe
** 5592 660     svchost.exe     0xca82b81ef2c0  4       -       0       False   2024-02-01 19:48:31.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\system32\svchost.exe -k LocalService -p -s BthAvctpSvc   C:\Windows\system32\svchost.exe
** 3040 660     svchost.exe     0xca82b3df5080  6       -       0       False   2024-02-01 19:48:25.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k NetSvcs -p -s iphlpsvc  C:\Windows\System32\svchost.exe
** 2544 660     svchost.exe     0xca82b8e84340  9       -       0       False   2024-02-01 19:50:26.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\svchost.exe    C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s wscsvc       C:\Windows\System32\svchost.exe
* 844   524     fontdrvhost.ex  0xca82b299d080  6       -       0       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\fontdrvhost.exe        "fontdrvhost.exe"       C:\Windows\system32\fontdrvhost.exe
532     516     csrss.exe       0xca82b287f140  13      -       1       False   2024-02-01 19:48:23.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\csrss.exe      %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16        C:\Windows\system32\csrss.exe
624     516     winlogon.exe    0xca82b28cb080  4       -       1       False   2024-02-01 19:48:23.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\winlogon.exe   winlogon.exe    C:\Windows\system32\winlogon.exe
* 364   624     LogonUI.exe     0xca82b30a2080  0       -       1       False   2024-02-01 19:48:24.000000 UTC  2024-02-01 19:48:37.000000 UTC  \Device\HarddiskVolume3\Windows\System32\LogonUI.exe    -       -
* 372   624     dwm.exe 0xca82b30a3080  14      -       1       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\dwm.exe        "dwm.exe"       C:\Windows\system32\dwm.exe
* 4508  624     userinit.exe    0xca82b7426340  0       -       1       False   2024-02-01 19:48:26.000000 UTC  2024-02-01 19:48:52.000000 UTC  \Device\HarddiskVolume3\Windows\System32\userinit.exe   -       -
** 4568 4508    explorer.exe    0xca82b7440340  55      -       1       False   2024-02-01 19:48:26.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\explorer.exe    C:\Windows\Explorer.EXE C:\Windows\Explorer.EXE
*** 7780        4568    OneDrive.exe    0xca82b814a0c0  21      -       1       True    2024-02-01 19:48:42.000000 UTC  N/A     \Device\HarddiskVolume3\Users\alex\AppData\Local\Microsoft\OneDrive\OneDrive.exe        "C:\Users\alex\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background   C:\Users\alex\AppData\Local\Microsoft\OneDrive\OneDrive.exe
*** 7540        4568    SecurityHealth  0xca82b7858080  3       -       1       False   2024-02-01 19:48:41.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\SecurityHealthSystray.exe      "C:\Windows\System32\SecurityHealthSystray.exe"     C:\Windows\System32\SecurityHealthSystray.exe
*** 7684        4568    vmtoolsd.exe    0xca82b7dbe080  8       -       1       False   2024-02-01 19:48:41.000000 UTC  N/A     \Device\HarddiskVolume3\Program Files\VMware\VMware Tools\vmtoolsd.exe  "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr        C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
*** 4628        4568    ChromeSetup.ex  0xca82b830a300  4       -       1       True    2024-02-01 19:48:50.000000 UTC  N/A     \Device\HarddiskVolume3\Users\alex\Downloads\ChromeSetup.exe    "C:\Users\alex\Downloads\ChromeSetup.exe"  C:\Users\alex\Downloads\ChromeSetup.exe
* 836   624     fontdrvhost.ex  0xca82b299c140  6       -       1       False   2024-02-01 19:48:24.000000 UTC  N/A     \Device\HarddiskVolume3\Windows\System32\fontdrvhost.exe        "fontdrvhost.exe"       C:\Windows\system32\fontdrvhost.exe
                                                            
```
:::


`vol -f ~/Desktop/159-Ramnit/memory.dmp windows.cmdline | grep .exe`
:::spoiler Result
```rust
320gresssmss.exe        \SystemRoot\System32\smss.exe
448     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
524     wininit.exe     wininit.exe
532     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
624     winlogon.exe    winlogon.exe
660     services.exe    C:\Windows\system32\services.exe
676     lsass.exe       C:\Windows\system32\lsass.exe
808     svchost.exe     C:\Windows\system32\svchost.exe -k DcomLaunch -p
836     fontdrvhost.ex  "fontdrvhost.exe"
844     fontdrvhost.ex  "fontdrvhost.exe"
928     svchost.exe     C:\Windows\system32\svchost.exe -k RPCSS -p
984     svchost.exe     C:\Windows\system32\svchost.exe -k DcomLaunch -p -s LSM
364     LogonUI.exe     -
372     dwm.exe "dwm.exe"
740     svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s gpsvc
1068    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s lmhosts
1136    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog
1144    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule
1156    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s ProfSvc
1164    svchost.exe     C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService
1172    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s TimeBrokerSvc
1260    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p
1384    svchost.exe     C:\Windows\system32\svchost.exe -k LocalService -p -s nsi
1420    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s UserManager
1452    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp
1644    svchost.exe     C:\Windows\system32\svchost.exe -k LocalService -p -s DispBrokerDesktopSvc
1684    svchost.exe     C:\Windows\System32\svchost.exe -k NetworkService -p -s NlaSvc
1716    svchost.exe     C:\Windows\system32\svchost.exe -k LocalService -p -s EventSystem
1724    svchost.exe     C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s SysMain
1740    svchost.exe     C:\Windows\System32\svchost.exe -k netsvcs -p -s Themes
1844    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s SENS
1916    svchost.exe     C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s AudioEndpointBuilder
1932    svchost.exe     C:\Windows\system32\svchost.exe -k LocalService -p -s FontCache
1944    svchost.exe     C:\Windows\System32\svchost.exe -k LocalService -p -s netprofm
2004    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p -s WinHttpAutoProxySvc
2092    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
2244    svchost.exe     C:\Windows\system32\svchost.exe -k NetworkService -p -s Dnscache
2280    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
2288    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p
2328    svchost.exe     C:\Windows\system32\svchost.exe -k appmodel -p -s StateRepository
2384    svchost.exe     C:\Windows\System32\svchost.exe -k netsvcs -p -s ShellHWDetection
2484    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNoNetworkFirewall -p
2500    svchost.exe     C:\Windows\System32\svchost.exe -k NetworkService -p -s DoSvc
2564    spoolsv.exe     C:\Windows\System32\spoolsv.exe
2612    svchost.exe     C:\Windows\system32\svchost.exe -k LocalService -p
2704    svchost.exe     C:\Windows\System32\svchost.exe -k NetworkService -p -s LanmanWorkstation
2760    sihost.exe      sihost.exe
2776    svchost.exe     C:\Windows\system32\svchost.exe -k UnistackSvcGroup -s CDPUserSvc
2864    svchost.exe     C:\Windows\system32\svchost.exe -k UnistackSvcGroup -s WpnUserService
2876    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s Winmgmt
2912    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s IKEEXT
2920    svchost.exe     C:\Windows\system32\svchost.exe -k NetworkServiceNetworkRestricted -p -s PolicyAgent
2972    svchost.exe     C:\Windows\system32\svchost.exe -k NetworkService -p -s CryptSvc
2988    svchost.exe     C:\Windows\System32\svchost.exe -k utcsvc -p
2996    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS
3040    svchost.exe     C:\Windows\System32\svchost.exe -k NetSvcs -p -s iphlpsvc
2872    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s TokenBroker
3116    taskhostw.exe   taskhostw.exe {222A245B-E637-4AE9-A93F-A59CA119A75E}
3128    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s LanmanServer
3160    svchost.exe     C:\Windows\system32\svchost.exe -k LocalService -p -s SstpSvc
3208    svchost.exe     C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TrkWks
3248    VGAuthService.  "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
3256    vm3dservice.ex  C:\Windows\system32\vm3dservice.exe
3288    wlms.exe        C:\Windows\system32\wlms\wlms.exe
3296    vmtoolsd.exe    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
3356    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s WpnService
3420    svchost.exe     C:\Windows\System32\svchost.exe -k LocalService -p -s WdiServiceHost
3544    vm3dservice.ex  vm3dservice.exe -n
3692    svchost.exe     C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s TabletInputService
3852    svchost.exe     C:\Windows\System32\svchost.exe -k netsvcs
3936    ctfmon.exe      "ctfmon.exe"
3104    svchost.exe     C:\Windows\system32\svchost.exe -k LocalService -p -s CDPSvc
4276    dllhost.exe     C:\Windows\system32\dllhost.exe /Processid:{02D4B3F1-FD88-11D1-960D-00805FC79235}
4416    svchost.exe     C:\Windows\system32\svchost.exe -k wsappx -p -s AppXSvc
4492    WmiPrvSE.exe    C:\Windows\system32\wbem\wmiprvse.exe
4508    userinit.exe    -
4568    explorer.exe    C:\Windows\Explorer.EXE
4796    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -s RmSvc
4836    msdtc.exe       C:\Windows\System32\msdtc.exe
3152    taskhostw.exe   taskhostw.exe
3228    svchost.exe     C:\Windows\System32\svchost.exe -k wsappx -p -s ClipSVC
4760    svchost.exe     C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s WdiSystemHost
5132    svchost.exe     C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p -s PcaSvc
5220    svchost.exe     C:\Windows\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc
5676    StartMenuExper  "C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" -ServerName:App.AppXywbrabmsek0gm3tkwpr5kwzbs55tkqay.mca
5932    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s UsoSvc
5948    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
2128    SearchApp.exe   "C:\Windows\SystemApps\Microsoft.Windows.Search_cw5n1h2txyewy\SearchApp.exe" -ServerName:CortanaUI.AppX8z9r6jm96hw4bsbneegw0kyxx296wr9t.mca
6216    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
6252    SearchIndexer.  C:\Windows\system32\SearchIndexer.exe /Embedding
6504    svchost.exe     C:\Windows\system32\svchost.exe -k appmodel -p -s camsvc
6964    LockApp.exe     "C:\Windows\SystemApps\Microsoft.LockApp_cw5n1h2txyewy\LockApp.exe" -ServerName:WindowsDefaultLockScreen.AppX7y4nbzq37zn4ks9k7amqjywdat7d3j2z.mca
7068    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
5592    svchost.exe     C:\Windows\system32\svchost.exe -k LocalService -p -s BthAvctpSvc
2928    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
7484    smartscreen.ex  C:\Windows\System32\smartscreen.exe -Embedding
7540    SecurityHealth  "C:\Windows\System32\SecurityHealthSystray.exe" 
7580    SecurityHealth  C:\Windows\system32\SecurityHealthService.exe
7684    vmtoolsd.exe    "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
7780    OneDrive.exe    "C:\Users\alex\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
6984    WmiPrvSE.exe    C:\Windows\system32\wbem\wmiprvse.exe
6500    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s Appinfo
7272    audiodg.exe     C:\Windows\system32\AUDIODG.EXE 0x4b8
4628    ChromeSetup.ex  "C:\Users\alex\Downloads\ChromeSetup.exe" 
7380    svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs -p -s lfsvc
4792    SkypeApp.exe    "C:\Program Files\WindowsApps\Microsoft.SkypeApp_14.53.77.0_x64__kzf8qxf38zg5c\SkypeApp.exe" -ServerName:App.AppXffn3yxqvgawq9fpmnhy90fr3y01d1t5b.mca
7948    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
5624    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
7112    ApplicationFra  C:\Windows\system32\ApplicationFrameHost.exe -Embedding
5912    WWAHost.exe     "C:\Windows\system32\wwahost.exe" -ServerName:Microsoft.MicrosoftOfficeHub.wwa
8420    dllhost.exe     C:\Windows\system32\DllHost.exe /Processid:{973D20D7-562D-44B9-B70B-5A0F49CCDF3F}
8728    WinStore.App.e  "C:\Program Files\WindowsApps\Microsoft.WindowsStore_11910.1002.5.0_x64__8wekyb3d8bbwe\WinStore.App.exe" -ServerName:App.AppXc75wvwned5vhz4xyxxecvgdjhdkgsdza.mca
8848    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
3832    svchost.exe     C:\Windows\System32\svchost.exe -k UnistackSvcGroup
7968    svchost.exe     C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s StorSvc
7040    SgrmBroker.exe  C:\Windows\system32\SgrmBroker.exe
2544    svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s wscsvc
7500    MicrosoftEdgeU  "C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /c
6080    svchost.exe     -
2964    WMIADAP.exe     wmiadap.exe /F /T /R
2608    ShellExperienc  "C:\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" -ServerName:App.AppXtk181tbxbce2qsex02s8tw7hfxa9xb3t.mca
2220    RuntimeBroker.  C:\Windows\System32\RuntimeBroker.exe -Embedding
8696    SearchProtocol  "C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe2_ Global\UsGthrCtrlFltPipeMssGthrPipe2 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon" 
3004    SearchFilterHo  "C:\Windows\system32\SearchFilterHost.exe" 0 812 816 824 8192 820 796 
```

:::


Ở bài Lab này mình sẽ dùng tool `voltatility3` để phân tích file dump.

Để tìm ra tên của tiến trình thực hiện các hành vi đáng ngờ mình dùng plugin `windows.cmdline` , `windows.pstree` và lọc `grep .exe`. Khi phân tích kết quả thì  mình thấy cơ bản toàn là file mặc định của Windows như `svchost.exe`, `dllhost.exe`, `taskhostw.exe`. Ban đầu mình chẳng thấy có file nào mà tên nó độc lạ cả nhưng khi xem kỹ hơn thì mình thấy có một file được chạy từ folder `Downloads` duy nhất là `ChromeSetup.exe`. Cho nên mình khẳng định đây là file được tải về từ bên ngoài nên khả năng đây là file độc hại được nhắc tới. Và kết quả đúng như mình đoán đáp án là `ChromeSetup.exe`

![image](https://hackmd.io/_uploads/SJHsXXEFZe.png)


> Flag: ChromeSetup.exe


### Q2:What is the exact path of the executable for the malicious process?

Ở đây ta sẽ xác định ra nơi lưu tiến trình được đánh dâu là độc hại kia. Như kết quả của các lệnh chạy từ câu trên mình biết được rằng nơi lưu trữ của nó nằm ở thư mục Downloads của người dùng **alex**: `C:\Users\alex\Downloads\ChromeSetup.exe`

![image](https://hackmd.io/_uploads/B1p6tzSYbg.png)

> Flag: C:\Users\alex\Downloads\ChromeSetup.exe

### Q3: Identifying network connections is crucial for understanding the malware's communication strategy. What IP address did the malware attempt to connect to?

Khi đã xác định được tệp mã độc mình sẽ cần đi tìm các hoạt động giao tiếp, kết nối mạng của nó để điều tra sâu hơn. Mình biết được là tool `volatility3` có option scan network là `windows.netscan`, mình sẽ dùng cái này kết hợp với option lọc ra chính xác chương trình độc hại kia để xem có hoạt động mạng nào không.

![image](https://hackmd.io/_uploads/SJTnhMStWl.png)

![image](https://hackmd.io/_uploads/ByMV3MSFZg.png)

Qua kết quả mình thấy rằng malware đang cố kết nối tới IP `58.64.204.181` và nó đang thực hiện việc bắt tay ba bước do có cờ SYN_SENT đã được gửi.

> Flag: 58.64.204.181

### Q4: To determine the specific geographical origin of the attack, Which city is associated with the IP address the malware communicated with?

Khi đã biết được IP mà malware cố gắng giao tiếp ta có thể kết luận đây chính là nơi mà hacker đặt server khởi tạo cho cuộc tấn công kế tiếp. Xác định ra được vị trí địa lý có thể giúp ích cho việc phân loại các hành vi tấn công của attacker sau này. Ở đây mình tra thông tin vị trí địa lý trên trang [VirusTotal detection report](https://www.virustotal.com/gui/file/1ac890f5fa78c857de42a112983357b0892537b73223d7ec1e1f43f8fc6b7496/detection).

Kết quả thu được là tại Hong Kong
![image](https://hackmd.io/_uploads/rJxekXBYWe.png)

> Flag: Hong Kong

### Q5: Hashes serve as unique identifiers for files, assisting in the detection of similar threats across different machines. What is the SHA1 hash of the malware executable?

Việc tìm ra được hash của malware là rất hữu ích để giúp phát hiện nhanh hơn những cuộc tấn công trước đó có dùng cùng malware điều đó sẽ giảm thời gian cho việc phòng ngừa và phát hiện malware trên những máy tính khác dùng chung một mạng. 

Do file được cấp chỉ là file memory dump nên mình không thể tính hash trực tiếp được. Mình check các chức năng có liên quan tới việc tìm hash của tool `volatility3` thì thấy có chức năng mình cần là `windows.hashdump.Hashdump` và `windows.registry.hashdump.Hashdump`

![image](https://hackmd.io/_uploads/rJwjx7StWg.png)

Chạy cả hai option mình thu được kết quả như sau:
![image](https://hackmd.io/_uploads/SyoyQQHFbl.png)


User |   rid  |   lmhash | nthash
|---|---|---|---|
Administrator  | 500   |  aad3b435b51404eeaad3b435b51404ee  |      31d6cfe0d16ae931b73c59d7e0c089c0
Guest |  501   |  aad3b435b51404eeaad3b435b51404ee      |  31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount | 503   |  aad3b435b51404eeaad3b435b51404ee   |     31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount   |   504   |  aad3b435b51404eeaad3b435b51404ee   |     99e3ca20a052ae6618bcb0ed4b9955ed
Workstation  |   1001  |  aad3b435b51404eeaad3b435b51404ee       | 64f12cddaa88057e06a81b54e73b949b
alex  |  1002  |  aad3b435b51404eeaad3b435b51404ee       | 64f12cddaa88057e06a81b54e73b949b


Tuy nhiên thì thông tin này lại không hưu ích nên mình phải dump file `exe` đó ra để tính hash, mình sẽ dùng tool với option `windows.dumpfiles.DumpFiles` để trích xuất file. 

![image](https://hackmd.io/_uploads/r14kHmHK-e.png)

![image](https://hackmd.io/_uploads/SyQnD7rYZg.png)

Ở đây mình dùng `--filter` để tool nó tự tìm ra file có tên `ChromeSetup`, và mình thu được 2 file.

![image](https://hackmd.io/_uploads/SJGLtmHF-g.png)

Kiểm tra thông tin của 2 file thì mình biết được có một file chỉ là `DataSectionObject` còn file còn lại `ImageSectionObject` mới là ảnh đĩa chứa đầy đủ thông tin của file gốc `ChromeSetup.exe`
![image](https://hackmd.io/_uploads/By0hKmBFbe.png)

Sau đó mình dùng lệnh `sha1sum` để tính hash và thu được chuỗi hash: `280c9d36039f9432433893dee6126d72b9112ad2`

![image](https://hackmd.io/_uploads/HyPq9XSKbl.png)

>Flag: 280c9d36039f9432433893dee6126d72b9112ad2


Đã có được hash vậy mình sẽ tra cứu trên VirusTotal để tìm hiểu thêm
[VirusTotal detection report](https://www.virustotal.com/gui/file/1ac890f5fa78c857de42a112983357b0892537b73223d7ec1e1f43f8fc6b7496/detection)


![image](https://hackmd.io/_uploads/ryhX6QHtWe.png)

Đây là malware thuộc loại `virus` và `trojan` và thuộc dòng persistance nó giả dạng là ứng dụng Chrome hoạt động âm thầm bên cạnh đó nó thực hiện các hành vi như sửa đổi Registry Key để có thể ẩn mình khỏi hệ thống AV, IDS, IPS. 

### Q6: Examining the malware's development timeline can provide insights into its deployment. What is the compilation timestamp for the malware?

Ta cần tìm ra thời điểm mà malware này được phát triển để có thể hiểu rõ  **"kẻ tấn công là ai"**  thông qua 4 manh mối: 

-   **Định danh:**  Giờ biên dịch code tiết lộ múi giờ sinh hoạt, giúp phân biệt hacker làm việc theo giờ hành chính (nhà nước bảo trợ) hay hacker tự do.
-   **Đánh giá rủi ro:**  Code vừa biên dịch xong đã tấn công ngay =  **Có chủ đích**  (nguy hiểm cao). Code cũ từ nhiều năm trước =  **Ngẫu nhiên**  (nguy hiểm thấp).
-   **Quy mô:**  Nhiều file khác nhau có cùng một giây biên dịch chính xác là bằng chứng của một chiến dịch tấn công hàng loạt.
-   **Vạch trần:**  Sự sai lệch giữa "thời gian biên dịch" và "thời gian tạo file" tố cáo hành vi cố tình làm giả bằng chứng của hacker.

**"Timestomping"** — kỹ thuật hacker cố tình chỉnh ngày tạo file lùi về quá khứ để ngụy trang thành file hệ thống vô hại.


Qua report trên VirusTotal mình biết được thời gian malware được phát triển là:    `2019-12-01 08:36:04 UTC`

![image](https://hackmd.io/_uploads/SJntiEBFZl.png)

> Flag: 2019-12-01 08:36


### Q7: Identifying the domains associated with this malware is crucial for blocking future malicious communications and detecting any ongoing interactions with those domains within our network. Can you provide the domain connected to the malware?

Phát hiện ra domain mà malware giao tiếp kêt nối tới sẽ hữu ích cho việc tạo rules phát hiện những hành vị tương tự sau này.

Qua thông tin trên Virustotal mình thấy malware có kết nối tới domain: `dnsnb8.net`, chi tiết hơn là tới subdomain `ddos` để thực hiện hành vi tải những file mã độc về máy nạn nhân.

![image](https://hackmd.io/_uploads/SyqkhNBF-l.png)

> Flag: dnsnb8.net




