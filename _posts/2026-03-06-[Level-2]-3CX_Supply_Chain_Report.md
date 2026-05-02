---
title: '[Level-2]-3CX_Supply_Chain_Report'
date: 2026-03-06

---

# Lab Report - 3CX Supply Chain
**DatHN5 - SO3 - FSAS**



**Category:**
[Threat Intel](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=threat-intel)

**Tactics:**
[Persistence](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=persistence), [Privilege Escalation](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=privilege-escalation), [Defense Evasion](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=defense-evasion), [Discovery](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=discovery)

**Tool:**
[VirusTotal](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=virustotal)


### Scenario
A large multinational corporation heavily relies on the 3CX software for phone communication, making it a critical component of their business operations. After a recent update to the 3CX Desktop App, antivirus alerts flag sporadic instances of the software being wiped from some workstations while others remain unaffected. Dismissing this as a false positive, the IT team overlooks the alerts, only to notice degraded performance and strange network traffic to unknown servers. Employees report issues with the 3CX app, and the IT security team identifies unusual communication patterns linked to recent software updates.

As the threat intelligence analyst, it's your responsibility to examine this possible supply chain attack. Your objectives are to uncover how the attackers compromised the 3CX app, identify the potential threat actor involved, and assess the overall extent of the incident. 

## Write up

Tình huống là một công ty đang bị phụ thuộc vào ứng dụng 3CX để liên lạc. Sau khi ứng dụng kia update thì các tool Antivirus đã đánh cờ cảnh báo do phát hiện được các trường hợp lẻ tẻ của phần mềm bị xóa khỏi một số máy trạm trong khi những máy khác vẫn không bị ảnh hưởng. Loại bỏ điều này vì cho rằng kết quả dương tính giả, nhóm CNTT bỏ qua các cảnh báo, chỉ nhận thấy hiệu suất bị suy giảm và lưu lượng truy cập mạng lạ đến các máy chủ không xác định. Và sau khi nhận được report từ nhân viên với ứng dụng 3CX, đội IT đã tìm ra điểm bất thường trong hành vi giao tiếp của app đó dẫn tới bản update gần đây. Và nhiệm vụ của ta là phân tích những mối nguy hại liên quan tới ứng dụng đó.

Ta được cung cấp một file `msi`, đây là file installer chuyên để cài các ứng dụng trên Windows.
![image](https://hackmd.io/_uploads/r1rWOOftWl.png)

### Q1: Understanding the scope of the attack and identifying which versions exhibit malicious behavior is crucial for making informed decisions if these compromised versions are present in the organization. How many versions of 3CX running on Windows have been flagged as malware?

Để thu gọn lại phạm vi phân tích ta cần xác định chính xác được chính xác phiên bản nào của ứng dụng 3CX bị gắn cờ là Malware. Điều này là quan trọng để ta có thể xác định được những máy nào đang bị xâm phạm do bản cập nhật của ứng dụng kia. 

Để xác định được thì thông tin file kia là không thể nên theo gợi ý mình tìm tới các bài Report liên quan tới vụ tấn công ứng dụng 3CX để điều tra sâu hơn.

Sau khi tra cứu các blog/report minh tìm thấy thông tin sau: có hai version bị ảnh hưởng đối với bản Win, và 3 bản trên Mac. Từ đó ta có thể kết luận có hai phiên bản trên Win bị ảnh hưởng
![image](https://hackmd.io/_uploads/rJEe6uGF-l.png)

> Flag: 2


### Q2: Determining the age of the malware can help assess the extent of the compromise and track the evolution of malware families and variants. What's the UTC creation time of the .msi malware?

Một thông tin quan trọng khi phân tích Malware là ta cần phải biết được tuổi của Malware đó để có thể đánh giá được những thông tin liên quan tới quy mô của cuộc tấn công và đê theo vết được những biến thể/ họ hàng được phát triển sau này. Ở đây ta sẽ đi tìm thời gian của Malware này được tạo ra.

Dựa vào gợi ý ta sẽ đi phân tích metadata của file `msi` kia, thông tin metadata rất hữu ích, mình có thể biết được Creat Time của file là : `Mon Mar 13 06:33:26 2023`, và chuyển sang dạng UTC ta có kết quả là `2023-03-13 06:33`
![image](https://hackmd.io/_uploads/HyxxyFMFZe.png)

> Flag: 2023-03-13 06:33 




### Q3: Executable files (.exe) are frequently used as primary or secondary malware payloads, while dynamic link libraries (.dll) often load malicious code or enhance malware functionality. Analyzing files deposited by the Microsoft Software Installer (.msi) is crucial for identifying malicious files and investigating their full potential. Which malicious DLLs were dropped by the .msi file?

Thông thường các file thực thi `exe` được sử dụng là malware pyload chính hoặc thứ cấp, trong khi các file `dll` sẽ là nơi mà malware sẽ tải những đoạn mã độc hại hoặc tải những đoạn mã để tăng cường chức năng của chúng. Và hành vi của malware thường là drop - xoá đi một file `dll` nào đó mặc định của hệ thống rồi load lại với file `dll` độc hại khác. Mục tiêu của ta ở đây là tìm ra file `dll` đã bị xoá bởi `.msi` file, từ file `.msi` được cung cấp ta có thể tìm ra những file liên quan được tải về.

Theo như gợi ý ta sẽ dùng cli tool tên là [msiinfo ](https://manpages.ubuntu.com/manpages/focal/man1/msiinfo.1.html) , chuyên dùng để trích xuất thông tin từ file `.msi`.

![image](https://hackmd.io/_uploads/Hk8xMKGFbx.png)

![image](https://hackmd.io/_uploads/BJl6fFftbe.png)

Dùng lệnh streams ta biết được những file được dùng bới file `msi` kia.

![image](https://hackmd.io/_uploads/rkJ57YMtbe.png)

Ở bước này ta vẫn chưa thấy có file `dll` nào show ra ngay nên ta cần trích xuất các file ra để tìm thêm các thông tin chi tiết hơn

Sau khi dùng lệnh `msiextract` để trích xuất các thông tin chi tiết ta nhận được kết quả như sau
    - 1 file `exe`
    - 1 file update
    - 1 file xml
    - 1 floder chứa các file khác liên quan tới ứng dụng 3CX

![image](https://hackmd.io/_uploads/Syz0NFfYZe.png)


Khám phá folder `app` được trích xuất ra ta tìm thấy các file `dll` đang ngờ như `d3dcompiler_47.dll` và `ffmpeg.dll` do những file `dll` thường không được đặt tên với các ký hiệu số thay chữ như kia. 
File `ffmpeg.dll` như mình biết được thì nó có các chức năng dùng để mã hoá, giải mã những thông tin quan trọng nên có thể đã bị xâm phạm để phục vụ mục đích của malware.

![image](https://hackmd.io/_uploads/ryaUItGtWl.png)

Để kiểm chứng xác thực nhất mình sẽ lấy mã hash của các file `dll` kia rồi tra cứu trên `VirusTotal` để kết luận.

Ở đây mình sẽ lấy mã hash loại SHA-256 do được tin tưởng và dùng rộng rãi
`sha256sum *.dll > hash-file.txt`

![image](https://hackmd.io/_uploads/ByxpPFfYWg.png)



Có 4 file `dll` dưới đây là file sạch
> ```
> libEGL.dll
> libGLESv2.dll
> vk_swiftshader.dll
> vulkan-1.dll


![Screenshot 2026-03-02 105046](https://hackmd.io/_uploads/SyCIKFMtZx.png)

![Screenshot 2026-03-02 105109](https://hackmd.io/_uploads/HyAUtKztZg.png)

![Screenshot 2026-03-02 105123](https://hackmd.io/_uploads/S108tKGFbl.png)

![Screenshot 2026-03-02 105134](https://hackmd.io/_uploads/r1RIKYfYbx.png)


Còn 2 file dưới này là mã độc
> ```
> d3dcompiler_47.dll: 11be1803e2e307b647a8a7e02d128335c448ff741bf06bf52b332e0bbf423b03
> ffmpeg.dll: 7986bbaee8940da11ce089383521ab420c443ab7b15ed42aed91fd31ce833896
> ```

![image](https://hackmd.io/_uploads/BkVJ5FfF-e.png)

![image](https://hackmd.io/_uploads/rkGl9KfY-x.png)


Từ đây mình có thể kết luận được đáp án cần tìm là `d3dcompiler_47.dll` và
`ffmpeg.dll`

> Flag: d3dcompiler_47.dll,ffmpeg.dll

### Q4: Recognizing the persistence techniques used in this incident is essential for current mitigation strategies and future defense improvements. What is the MITRE Technique ID employed by the .msi files to load the malicious DLL?


Ta đã biết được rằng malware này sử dụng file `.msi` như là công cụ để tải và liên kết các đoạn mã độc với nhau, và ta cần xác định những kỹ thuật persistance được sử dụng để có thể đưa ra phương án giảm thiểu thiệt hại và những phương án phòng thủ bảo vệ sau này. Ta sẽ sử dụng framwork MITRE để mapping tìm kiếm kỹ thuật được dùng bởi file `.msi` để tải các file `dll` độc hại.

Ở đây để có thể tìm nhanh hơn mình search google về các kỹ thuật liên quan tới việc drop  file `dll` minh thu được kết quả là các technique ID **T1574** và cụ thể hơn là **T1574.001** hoặc **T1574.002** 

![image](https://hackmd.io/_uploads/rkvyl9zF-e.png)

Tiếp tục tra về Technique T1574 trên MITRE mình thu được thông tin về các kỹ thuật như DLL Sideloading và DLL Search Oder Hijacking. Tổng quan về 2 phương pháp này thì kẻ tấn công sẽ tìm cách xoá đi một hoặc nhiều file `dll` sạch của Windows và thay bằng những file `dll` độc hại để khi những ứng dụng uy tín khởi chạy tìm tới các file dll để chạy thì mã độc sẽ được liên kết và thực thi, việc phân mảnh ra nhiều file `dll` khiến cho việc phân tích sau này trờ nên khó khăn hơn.

![image](https://hackmd.io/_uploads/B1l0OlcGY-e.png)


Ta kết luận Technique ID là T1574

> Flag: T1574


### Q5: Recognizing the malware type (threat category) is essential to your investigation, as it can offer valuable insight into the possible malicious actions you'll be examining. What is the threat category of the two malicious DLLs?

Việc chúng ta nhận diện được loại Malware sẽ giúp ích nhiều cho việc phân tích những hành vi của malware và các phương án phòng thủ sau này, và nhiệm vụ của ta là tìm ra loại Malware được sử dụng trong bài này.

Dựa vào thông tin tra cứu được trên VirusTotal mình biết được 2 file mã độc kia đều thuộc loại Trojan tức là giả mạo phần mềm legit để tải và thực thi các đoạn mã độc. Kết luận loại malware là Trojan.

![image](https://hackmd.io/_uploads/Bk673oMYWe.png)

![image](https://hackmd.io/_uploads/SJLS2sGFWx.png)



> Flag: Trojan

### Q6: As a threat intelligence analyst conducting dynamic analysis, it's vital to understand how malware can evade detection in virtualized environments or analysis systems. This knowledge will help you effectively mitigate or address these evasive tactics. What is the MITRE ID for the virtualization/sandbox evasion techniques used by the two malicious DLLs?

Việc phân tích Malware không chỉ dừng lại ở mức static-tức chỉ xem code tĩnh mà còn phải phân tích động nữa tức là cần phải thực thi và quan sát các hành vi của malware trong môi trường kiểm soát. Việc này giúp phát hiện ra các hoạt động và hành vi ẩn của malware mà đôi khi static không thể bao phủ tới, bên cạnh đó cũng giúp đưa ra các giải pháp để đối phó với các tactic ẩn mình của malware.

Mục tiêu của ta ở đây là tìm ra MITRE ID được sửa dụng bởi hai file `dll` độc hại kia nhằm ẩn mình khỏi môi trường sanbox/ virtualization để tránh bị phát hiện trong quá trình dynamic analysis.

Qua thông tin trên Virustotal mình biết được kỹ thuật ẩn mình được sủa dụng ở đây là **T1497**

Bên cạnh ẩn mình khỏi môi trường ảo hoá hai file mã độc này còn có cả kỹ thuật ẩn mình khỏi các trình Debugger nữa

![image](https://hackmd.io/_uploads/r19yxhMFbe.png)

![image](https://hackmd.io/_uploads/SypMlnGtZg.png)

![image](https://hackmd.io/_uploads/r1dFknzKWg.png)




***Key Differences***
Feature | T1497 - Virtualization/Sandbox Evasion | T1622 - Debugger Evasion
--------|--------|--------|
Primary Goal | Detect automated analysis (sandboxes/VMs). | Detect manual analysis (debuggers).
Target Environment | VirtualBox, VMware, Hyper-V, Sandboxie. | x64dbg, OllyDbg, WinDbg, IDA Pro.
Methods | Checks for specific files, DLLs, registry keys, or MAC addresses.	 | Uses API calls (IsDebuggerPresent), checks PEB (Process Environment Block).
Common Action | Terminates or delays execution if a VM is detected. | Changes behavior or conceals payload if a debugger is attached.



> Flag: T1497

### Q7: When conducting malware analysis and reverse engineering, understanding anti-analysis techniques is vital to avoid wasting time. Which hypervisor is targeted by the anti-analysis techniques in the ffmpeg.dll file?

Khi đã biết malware có kỹ thuật ẩn mình trong môi trường ao hoá, ta tiếp tục xem môi trường ảo hoá nào mà được nhắm tới để chống phân tích. Cụ thể ta sẽ tìm ra ứng dụng ảo hoá mà malware `ffmpeg.dll` nhắm tới.

![image](https://hackmd.io/_uploads/B1zCf3MYZg.png)

Dựa vào thông tin trên VirusTotal mình biết được hypervisor mà nó nhắm tới là VMware. Kết luận VMWare là đáp án cần tìm.

> Flag: VMWare

### Q8: Identifying the cryptographic method used in malware is crucial for understanding the techniques employed to bypass defense mechanisms and execute its functions fully. What encryption algorithm is used by the ffmpeg.dll file?

Khi đã biết được những thông tin cơ bản về hành vi của malware rồi thì điều quan trọng tiếp là cần phải xác minh ra cơ chế mã hoá của chúng. Đối với malware thì việc mã hoá được coi là key, có thể dùng để làm hỏng dữ liệu không thể khôi phục cũng như dùng để tống tiền nạn nhân. Xác định ra loại mã hoá mà malware dùng sẽ giúp ích cho việc phân tích các hành vi bypass cơ chế phòng thủ.

Phân tích trên Virustotal ta biết được việc mã hoá trên liên quan tới một loại technique là **T1027** 

![image](https://hackmd.io/_uploads/S1oNr3MtWg.png)

![image](https://hackmd.io/_uploads/SkOYr2zYZe.png)

Và phương pháp mã hoá được dùng bởi file `ffmpeg.dll` là **RC4**

![image](https://hackmd.io/_uploads/HyVkIhMKZg.png)


> Flag: RC4

### Q9: As an analyst, you've recognized some TTPs involved in the incident, but identifying the APT group responsible will help you search for their usual TTPs and uncover other potential malicious activities. Which group is responsible for this attack?

Mục tiêu của ta là tìm ra tổ chức đứng sau cuộc tấn công vào ứng dung 3CX. Để tìm ra tổ chức đó ta sẽ tra cứu các blog/report liên quan tới vụ tấn công này để tìm ra kẻ tình nghi đứng sau. Kết quả mình tìm được cho thấy tổ chức đó là **Lazarus**

![image](https://hackmd.io/_uploads/SJwCwhftZx.png)

![image](https://hackmd.io/_uploads/S1IXO3fFbl.png)

> Flag: Lazarus
