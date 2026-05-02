---
title: '[Level-4]-Andromeda-Bot-UNC4210'
date: 2026-03-20

---

# Lab Report - Andromeda Bot - UNC4210
**DatHN5 - SO3 - FSAS**
---

Analyze memory images and event logs using MemProcFS, EvtxECmd, and Timeline Explorer to identify Andromeda bot IOCs, reconstruct its infection timeline, and attribute it to an APT group. 

**Category**: Endpoint Forensics 
**Tactics**: Initial Access, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement, Command and Control 
**Tools**: MemProcFS, VirusTotal, Evtxcmd, Timeline Explorer

#### Scenario
As a member of the DFIR team at SecuTech, you're tasked with investigating a security breach affecting multiple endpoints across the organization. Alerts from different systems suggest the breach may have spread via removable devices. You’ve been provided with a memory image from one of the compromised machines. Your objective is to analyze the memory for signs of malware propagation, trace the infection’s source, and identify suspicious activity to assess the full extent of the breach and inform the response strategy.

### Write up
Tình huống
- Có 1 security breach ảnh hưởng tới mọi endpoint trong công ty
- Alert báo rằng nguồn gốc có thể tới từ thiết bị ngoại vi 
- Ta được cung cấp memory image từ 1 máy tính bị xâm nhập để phân tích cách malware lan truyền, nguồn gốc, các hành vi bất thường để dựng lại toàn cảnh vụ tấn công, đề xuất quy trình phản ứng sự cố.

---
#### Q1 Tracking the serial number of the USB device is essential for identifying potentially unauthorized devices used in the incident, helping to trace their origin and narrow down your investigation. What is the serial number of the inserted USB device?

Chạy tool MemProcFS để có thể trích xuất các thông tin hữu ích có trong file memory dump với lệnh `memprocfs -f memory.dump -forensic 1`

Kết quả là 1 thư mục tổng hợp các thông tin có trong dump dựng lại

![image](https://hackmd.io/_uploads/HyCpSkbsWx.png)


Thông tin của thiết bị ngoại vi USB được cắm vào máy tính được lưu ở Registry key USBTOR nắm ở dường dẫn `HKLM\SYSTEM\ControlSet001\Enum\USBTOR`

Mở folder registry theo đường dẫn trên mình thấy được thông tin mã serial của chiếc USB đã cắm vào máy

![image](https://hackmd.io/_uploads/rygQ3i6koWg.png)

>Flag: 7095411056659025437&0

---
#### Q2 Tracking USB device activity is essential for building an incident timeline, providing a starting point for your analysis. When was the last recorded time the USB was inserted into the system?

Thông tin các thiết bị kết nối qua cổng USB được lưu tại `HKLM\SYSTEM\ControlSet001\Services\USBTOR`

![image](https://hackmd.io/_uploads/rJHYwAJj-x.png)

![image](https://hackmd.io/_uploads/rJx5PCyi-e.png)

Và còn ở `py\reg\usb` 

![image](https://hackmd.io/_uploads/SJztCAyjZe.png)

![image](https://hackmd.io/_uploads/BJ8s0A1oZe.png)

>Flag: 2024-10-04 13:48

---
#### Q3 Identifying the full path of the executable provides crucial evidence for tracing the attack's origin and understanding how the malware was deployed. What is the full path of the executable that was run after the PowerShell commands disabled Windows Defender protections?

Để tìm ra file `exe` mà được khỏi chạy ngay sau khi 1 command trong Powershell dùng để tắt đi trình bảo vệ Windows Defender mình sẽ tìm tới eventlog để phân tích

Truy cập vào folder `misc\eventlog`, mình bắt đầu phân tích file log có dung lượng lơn nhất bằng cách dùng tool `EvtxECmd` để parse sang dạng CSV để đưa vào tool Timeline Explorer cho trực quan

![image](https://hackmd.io/_uploads/SkRhtkWi-g.png)

`EvtxECmd -f "ffffa6895662b6f0-Microsoft-Windows-Store%4Operational.evtx" --csv mwso`

![image](https://hackmd.io/_uploads/SJBlcyWiZg.png)

![image](https://hackmd.io/_uploads/rkLbqJWiZx.png)

Sau khi chạy tool `EvtxECmd` mình nhận được 1 file event log với format csv 

Mở file đó với tool Timeline Explorer mình bắt đầu phân tích các thông tin, sau một lúc thì mình tìm được full command thực hiện việc tắt trình Windows Defender protection như sau

![image](https://hackmd.io/_uploads/Sk3ubWWsZx.png)

```powershell!
Payload Data6
ParentCommandLine: "C:\Windows\System32\cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command "Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPreference -DisableBehaviorMonitoring $true; Set-MpPreference -DisableIOAVProtection $true; Set-MpPreference -DisableScriptScanning $true; Set-MpPreference -DisableBlockAtFirstSeen $true; Set-MpPreference -DisableCloudProtection $true; Set-MpPreference -DisableArchiveScanning $true; Set-MpPreference -SubmitSamplesConsent 2; sc stop WinDefend; sc config WinDefend start= disabled; sc stop SecurityHealthService; sc config SecurityHealthService start= disabled; Start-Process 'E:\hidden\Trusted Installer.exe'"

```
Phân tích command trên
- Các lệnh Set-MpPreference dùng để tắt các thành phần bảo vệ khác nhau:

| Command | Ý nghĩa |
|------|---------|
| Set-MpPreference -DisableRealtimeMonitoring $true            | Tắt bảo vệ thời gian thực  |
| Set-MpPreference -DisableBehaviorMonitoring $true            | Tắt giám sát hành vi       |
| Set-MpPreference -DisableIOAVProtection $true                | Tắt bảo vệ IO bằng Antivirus|
| Set-MpPreference -DisableScriptScanning $true                | Tắt quét mã script         |
| Set-MpPreference -DisableBlockAtFirstSeen $true              | Tắt tính năng "block at first seen" (ngăn chặn file lạ) |
| Set-MpPreference -DisableCloudProtection $true               | Tắt quét virus/tham vấn cloud|
| Set-MpPreference -DisableArchiveScanning $true               | Tắt quét file nén (archive)|
| Set-MpPreference -SubmitSamplesConsent 2                     | Không gửi mẫu nghi vấn về Microsoft (giảm khả năng nhận diện mới) |

- Các lệnh sc stop, sc config ... start= disabled dừng và vô hiệu hóa 2 dịch vụ bảo mật quan trọng:

| Command | Ý nghĩa |
|------|---------|
| sc stop WinDefend                 | Dừng dịch vụ Windows Defender   |
| sc config WinDefend start= disabled| Vô hiệu hóa tự khởi động Defender|
| sc stop SecurityHealthService     | Dừng dịch vụ Security Health    |
| sc config SecurityHealthService start= disabled | Không cho dịch vụ này tự bật lại    |

- Khởi chạy phần mềm `Trusted Installer.exe` tại đường dẫn 'E:\hidden\Trusted Installer.exe'

Tên file + đường dẫn không chính thống => đây là file mã độc

>Flag: E:\hidden\Trusted Installer.exe

---
#### Q4 Identifying the bot malware’s C&C infrastructure is key for detecting IOCs. According to threat intelligence reports, what URL does the bot use to download its C&C file?

Hash của file `Trusted Installer.exe`
- MD5=BC76BD7B332AA8F6AEDBB8E11B7BA9B6
- SHA256=9535A9BB1AE8F620D7CBD7D9F5C20336B0FD2C78D1A7D892D76E4652DD8B2BE7
- IMPHASH=7FA974366048F9C551EF45714595665E

![image](https://hackmd.io/_uploads/Hy2Skm-oWl.png)

Theo như thông tin từ virustotal mình thấy rằng malware đã contact tới 2 url để tải file `in.php` đó là `	http://anam0rph.su/in.php` và `	http://xdqzpbcgrvkj.ru/in.php`

![image](https://hackmd.io/_uploads/H1XLzm-o-x.png)

Một report khác thì phát hiện ra nhiều url hơn nhưng có điểm chung là đều cố gắng tải file `in.php`



---
#### Q5 Understanding the IOCs for files dropped by malware is essential for gaining insights into the various stages of the malware and its execution flow. What is the MD5 hash of the dropped .exe file?

Theo như thông tin trên virustotal thì malware đã drop 4 file .exe

![image](https://hackmd.io/_uploads/H1S1SmbjZl.png)

![image](https://hackmd.io/_uploads/S1qhDXWjbe.png)

Nhìn vào flow mà malware hoạt động thì có vẻ như file exe mà câu hỏi đề cập tới đó là file `Sahofivizu.exe` bởi đây là file exe bị malware dưới tên `Hu25VEa8Dr.exe` drop đầu tiên rồi khởi tạo tiến trình  từ file exe đó

![image](https://hackmd.io/_uploads/H1JRYQbo-e.png)

Kết hợp với thông tin Bundles Files (tất cả các file nằm bên trong file malware Trusted Installer.exe) trên virustotal nữa thì càng khẳng định rằng file mà ta đang tìm chính là file `Sahofivizu.exe`

MD5:  `7fe00cc4ea8429629ac0ac610db51993` 

> 7fe00cc4ea8429629ac0ac610db51993

---
#### Q6 Having the full file paths allows for a more complete cleanup, ensuring that all malicious components are identified and removed from the impacted locations. What is the full path of the first DLL dropped by the malware sample?



![image](https://hackmd.io/_uploads/r14FiQZibg.png)

Dựa vào timeline trong event log thì file Gozekeneka.dll được drop vào trước tiên

> C:\Users\Tomy\AppData\Local\Temp\Gozekeneka.dll

---
#### Q7 Connecting malware to APT groups is crucial for uncovering an attack's broader strategy, motivations, and long-term goals. Based on IOCs and threat intelligence reports, which APT group reactivated this malware for use in its campaigns?

[virustotal](https://www.virustotal.com/gui/file/9535a9bb1ae8f620d7cbd7d9f5c20336b0fd2c78d1a7d892d76e4652dd8b2be7/details)

[joesandbox](https://www.joesandbox.com/analysis/1336400/0/html)

[nec](https://www.nec.com/en/global/solutions/cybersecurity/blog/240823/index.html#anc-01)

[turla-galaxy-opportunity](https://cloud.google.com/blog/topics/threat-intelligence/turla-galaxy-opportunity/)


![image](https://hackmd.io/_uploads/Hk5fWEWiZe.png)

![image](https://hackmd.io/_uploads/H14HZ4-jZe.png)


![Screenshot 2026-03-25 164942](https://hackmd.io/_uploads/rknqlN-s-e.png)

![Screenshot 2026-03-25 164945](https://hackmd.io/_uploads/S1gsg4-j-x.png)

> Turla