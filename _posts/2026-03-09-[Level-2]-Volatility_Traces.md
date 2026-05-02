---
title: '[Level-2]-Volatility_Traces'
date: 2026-03-09

---

# Lab Report - Volatility Traces
  
**DatHN5 - SO3 - FSAS**

Analyze a memory dump using Volatility to identify malicious processes, persistence mechanisms, defense evasion techniques, and map them to MITRE ATT&CK. 

**Category**: Endpoint Forensics 
**Tactics**: Execution Persistence 
**Tool**: Volatility 3 (v2.7.0+ REQUIRED)

### Scenario

On May 2, 2024, a multinational corporation identified suspicious PowerShell processes on critical systems, indicating a potential malware infiltration. This activity poses a threat to sensitive data and operational integrity.

You have been provided with a memory dump (`memory.dmp`) from the affected system. Your task is to analyze the dump to trace the malware's actions, uncover its evasion techniques, and understand its persistence mechanisms.

## Write up

### Q1 Identifying the parent process reveals the source and potential additional malicious activity. What is the name of the suspicious process that spawned two malicious PowerShell processes?

Ta đươc cung cấp một file memory dump của máy tính Windows

![image](https://hackmd.io/_uploads/ryHPHzjKbe.png)

Trước tiên nhiệm vụ là xác định ra tiến trình đã spawn hai tiến trình PowerShell độc hại. 
Em có chạy lệnh sau với `windows.pstree` để tìm các mối liên hệ cha-con của các tiến trình **powershell**.


`./vol.py -f /home/ubuntu/Desktop/"Start here"/Artifacts/memory.dmp windows.pstree | grep powershell`
:::spoiler Result

```rust
6980ress459600.0powershell.exe	0xb882f10e9080	13	-	1	True	2024-05-02 06:57:59.000000 	N/A	\Device\HarddiskVolume3\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" Add-MpPreference -ExclusionPath "C:\Users\Lee\AppData\Local\Temp\InvoiceCheckList.exe"	C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
7656	4596	powershell.exe	0xb882f0db8080	13	-	1	True	2024-05-02 06:57:59.000000 	N/A	\Device\HarddiskVolume3\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" Add-MpPreference -ExclusionPath "C:\Users\Lee\AppData\Roaming\HcdmIYYf.exe"	C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
:::

Kết quả thu được là attacker đã dùng powershell để thêm whitelist vào MS Defender để cho malware không bị antivirus quét tới. 

Ở đây mình biết được tiến trình cha của `powershell.exe` là **4596** mà mình tìm ở kết quả lệnh `pstree` không ra nên minh dùng `psscan`

`./vol.py -f /home/ubuntu/Desktop/"Start here"/Artifacts/memory.dmp windows.psscan | grep 4596`
:::spoiler Result
```rust
7656ress4596	powershell.exe	0xb882f0db8080	13	-	1	True	2024-05-02 06:57:59.000000 	N/A	Disabled
2816	4596	RegSvcs.exe	0xb882f1010080	0	-	1	False	2024-05-02 06:58:00.000000 	2024-05-02 06:58:00.000000 	Disabled
4164	4596	RegSvcs.exe	0xb882f1029080	0	-	1	False	2024-05-02 06:58:00.000000 	2024-05-02 06:58:00.000000 	Disabled
6796	4596	RegSvcs.exe	0xb882f1031080	5	-	1	True	2024-05-02 06:58:00.000000 	N/A	Disabled
6448	4596	RegSvcs.exe	0xb882f1063080	0	-	1	False	2024-05-02 06:58:00.000000 	2024-05-02 06:58:00.000000 	Disabled
4596	3800	InvoiceCheckLi	0xb882f107e080	0	-	1	False	2024-05-02 06:57:42.000000 	2024-05-02 06:58:00.000000 	Disabled
3512	4596	schtasks.exe	0xb882f10e3080	0	-	1	False	2024-05-02 06:57:59.000000 	2024-05-02 06:57:59.000000 	Disabled
6980	4596	powershell.exe	0xb882f10e9080	13	-	1	True	2024-05-02 06:57:59.000000 	N/A	Disabled
```
:::

Kết quả thu được là `InvoiceCheckList.exe` chính là cái tiến trình được cho vào whitelist của Win Defender mà mình thấy ở bên trên

> Flag: InvoiceCheckList.exe

1. **Assessment Conclusion**
   **Khả năng cao là hành vi độc hại (Defense Evasion).**
   PowerShell đã chạy lệnh **`Add-MpPreference -ExclusionPath`** để **thêm các file `.exe` trong thư mục user vào danh sách loại trừ của Microsoft Defender**, giúp **malware không bị antivirus quét**.
   Đặc biệt đáng nghi vì:

   * File nằm trong **Temp và Roaming** (thường dùng để drop malware).
   * Tên file **`HcdmIYYf.exe`** có dạng **random**.
   * Exclusion được thêm **trực tiếp cho file thực thi**.

2. **Payload Extraction**

Command thực tế:

```powershell
Add-MpPreference -ExclusionPath "C:\Users\Lee\AppData\Local\Temp\InvoiceCheckList.exe"
Add-MpPreference -ExclusionPath "C:\Users\Lee\AppData\Roaming\HcdmIYYf.exe"
```

Ý nghĩa:

```text
Add-MpPreference      -> chỉnh cấu hình Microsoft Defender
-ExclusionPath        -> thêm file vào danh sách không bị quét
InvoiceCheckList.exe  -> file thực thi được Defender bỏ qua
HcdmIYYf.exe          -> file exe có tên random (rất đáng nghi)
```

3. **Attack Intent**

Mục đích của attacker:

```text
1. Drop malware vào thư mục user
2. Dùng PowerShell thêm file vào Defender Exclusion
3. Defender không quét file
4. Malware chạy mà không bị phát hiện
```

Phân loại MITRE:

**[T1562.001](https://attack.mitre.org/techniques/T1562/001/) – Impair Defenses (Modify Security Tools)**


---

### Q2 By determining which executable is utilized by the malware to ensure its persistence, we can strategize for the eradication phase. Which executable is responsible for the malware's persistence?


Từ kết quả cảu các lệnh ở câu trên mình biết được malware này dính dáng rất lơn tới PID 4596, và trong kết quả của việc chạy `psscan` mình thấy có tiến trình là `schtasks.exe`được gọi bởi malware nhằm mục đích chạy persistence.

![image](https://hackmd.io/_uploads/HypUI7jtbx.png)

![image](https://hackmd.io/_uploads/B1elmSXiFZx.png)

`schtasks.exe` là công cụ quản trị để Windows thực hiện việc tạo, sửa, xoá, chạy hay kết thúc những tác vụ tự động.

> Flag: schtasks.exe

1. Assessment Conclusion
Executable chịu trách nhiệm tạo persistence: schtasks.exe.
Malware InvoiceCheckLi...exe (PID 4596) đã gọi schtasks.exe để tạo Scheduled Task, giúp malware tự chạy lại sau reboot hoặc theo lịch, đảm bảo duy trì persistence trong hệ thống.

2. Payload Extraction
    ```
    Chuỗi process (timeline):

    2024-05-02 06:57:42
    PID 4596  -> InvoiceCheckLi.exe   (malware khởi chạy)

    2024-05-02 06:57:59
    PID 7656  -> powershell.exe
    Command:
    Add-MpPreference -ExclusionPath InvoiceCheckList.exe
    (Add Defender exclusion để né antivirus)

    2024-05-02 06:57:59
    PID 3512  -> schtasks.exe
    (Malware tạo Scheduled Task để persistence)

    2024-05-02 06:58:00
    PID 2816 / 4164 / 6796 / 6448 -> RegSvcs.exe
    (.NET execution / loader activity)
    ```
    Process tree:
    ```
    InvoiceCheckList.exe (PID 4596)
    │
    ├─ powershell.exe → Defender Exclusion
    │
    ├─ schtasks.exe → Persistence
    │
    └─ RegSvcs.exe → .NET payload execution
    ```
    Attack Intent

    Chuỗi tấn công của malware:
    ```
    1. User chạy InvoiceCheckList.exe (malware dropper)

    2. Malware chạy PowerShell
       → Add-MpPreference
       → bypass Microsoft Defender

    3. Malware chạy schtasks.exe
       → tạo Scheduled Task persistence

    4. Malware gọi RegSvcs.exe
       → chạy payload .NET / loader
    ```
    MITRE ATT&CK:
    ```
    T1053.005  – Scheduled Task (Persistence)
    T1562.001  – Modify Security Tools
    T1218.009  – RegSvcs Proxy Execution
    ```
---

### Q3 Understanding child processes reveals potential malicious behavior in incidents. Aside from the PowerShell processes, what other active suspicious process, originating from the same parent process, is identified?

![image](https://hackmd.io/_uploads/S1DFU7it-l.png)

Ngoài cái `schtasks.exe` thì mình còn phải tìm thêm tiến trình lạ mà có liên quan tới con malware, được malware gọi tới dùng là gì. Cũng từ kết quả của lệnh `psscan | grep 4596` mình thấy có tiến trình `RegSvcs.exe` có xuất hiện với tư cách là tiến trình con do malware gọi tới.

`RegSvsc.exe` là công cụ cho developer để cài đặt/đăng ký component **.NET** vào hệ thống COM+, giúp ứng dụng khác có thể sử dụng các component đó.
![image](https://hackmd.io/_uploads/Hy28PXoKZe.png)

Kẻ tấn công lợi dụng công cụ hợp pháp này để thực thi assembly **.NET** độc hại, giúp ẩn hoạt động dưới tiến trình hợp lệ của Windows (Living-off-the-Land).

> Flag: RegSvcs.exe


### Q4 Analyzing malicious process parameters uncovers intentions like defense evasion for hidden, stealthy malware. What PowerShell cmdlet used by the malware for defense evasion?


Để biết rằng attacker đã dùng hàm gì trong powershell để malware có thể né tránh khỏi antivirus quét, mình dùng lệnh sau để nhận dạng chi tiết
`./vol.py -f /home/ubuntu/Desktop/"Start here"/Artifacts/memory.dmp windows.cmdline | grep powershell`

![image](https://hackmd.io/_uploads/S1_ntXjYWg.png)
```!
6980resspowershell.exe	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" Add-MpPreference -ExclusionPath "C:\Users\Lee\AppData\Local\Temp\InvoiceCheckList.exe"
7656	powershell.exe	"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" Add-MpPreference -ExclusionPath "C:\Users\Lee\AppData\Roaming\HcdmIYYf.exe"

```

Kết hợp với kết quả ở câu 1 mình biết được khi chạy powershell attacker đã dùng hàm `Add-MpPreference` cùng với path tới malware để thực hiện kỹ thuật evasion

`Add-MpPreference` là một cmdlet trong PowerShell dùng để cấu hình các thiết lập của Windows Defender Antivirus. Nó thường được dùng để thêm ngoại lệ (exclusions) cho tệp tin, thư mục, hoặc quy trình không bị quét, nhằm tăng tốc độ hoặc ngăn chặn xung đột, cũng như thiết lập hành động mặc định cho các mối đe dọa
![image](https://hackmd.io/_uploads/SJhR97sKbl.png)

[Link-guide](https://quantrimang.com/cong-nghe/them-ngoai-le-trong-windows-defender-172110)

> Flag: Add-MpPreference

### Q5 Recognizing detection-evasive executables is crucial for monitoring their harmful and malicious system activities. Which two applications were excluded by the malware from the previously altered application's settings?

![image](https://hackmd.io/_uploads/rJh2iXoY-x.png)

Dựa vào kết quả chạy lệnh ở câu trên mình kết luận hai ứng dụng được miễn không phải quét antivirus đó là: `InvoiceCheckList.exe` và `HcdmIYYf.exe`

> Flag: InvoiceCheckList.exe,HcdmIYYf.exe
> 
### Q6 What is the specific MITRE sub-technique ID associated with PowerShell commands that aim to disable or modify antivirus settings to evade detection during incident analysis?

Như đã phân tích ở câu 2 nên mình kết luận rằng techique ID đó là [T1562.001](https://attack.mitre.org/techniques/T1562/001/)  – Modify Security Tools

![image](https://hackmd.io/_uploads/SkiAhmoFZg.png)


### Q7 Determining the user account offers valuable information about its privileges, whether it is domain-based or local, and its potential involvement in malicious activities. Which user account is linked to the malicious processes?

Cấu này hỏi tới tìa khoản người dùng có liên quan tới những tiến trình malware kia là gì. Trong các chức năng của tool mình thấy có chức năng trích xuất registry để tìm ra các user có hoạt động tại thời điểm đó là `windows.registry.userassist`

![image](https://hackmd.io/_uploads/S1tIyVjF-g.png)

Mình có chạy lệnh sau để tìm kiếm `./vol.py -f /home/ubuntu/Desktop/"Start here"/Artifacts/memory.dmp windows.registry.userassist | grep user`

![image](https://hackmd.io/_uploads/S1BueVsK-g.png)


Kết quả thì chỉ có 1 user hoạt động ngay lúc malware hoạt động đó là `Lee`

> Flag: Lee
