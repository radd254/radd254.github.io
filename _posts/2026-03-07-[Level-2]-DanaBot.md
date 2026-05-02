---
title: '[Level-2]-DanaBot'
date: 2026-03-07

---

# Lab Report - DanaBot
**DatHN5 - SO3 - FSAS**
---

**Category:**
[Network Forensics](https://cyberdefenders.org/blueteam-ctf-challenges/?categories=network-forensics)

**Tactics:**
[Execution](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=execution), [Command and Control](https://cyberdefenders.org/blueteam-ctf-challenges/?tactics=command-and-control)

**Tools:**
[Wireshark](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=wireshark), [VirusTotal](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=virustotal), [ANY.RUN](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=anyrun), [Network Miner](https://cyberdefenders.org/blueteam-ctf-challenges/?tools=network-miner)

**Scenario**
The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.

## Write Up

Tình huống là đội SOC phát hiện ra lưu lượng mạng bất thường và tìm ra một máy tính đã bị xâm phạm, và ta cần phân tích file PCAP để tìm hiểu chi tiết về sự cố trên xem nó đã xảy ra như thế nào.

Dựa vào tag Execution và Command and Control mình đoán được là có một malware đã xâm nhập vào máy nạn nhân và attacker thực hiện việc kiểm soát máy nạn nhân từ xa để thực thi cách hành vi độc hại.


**Q1: Which IP address was used by the attacker during the initial access?**

Trước hết ta cần xác định IP của máy hacker dùng trong phase khởi tạo truy cập. Đây là thông tin quan trọng để dễ truy vết hành vi của attacker về sau.

Tập trung vào những gói tin ban đầu mình nhận thấy rằng có một query tới trang web `portfolio.serveirc.com` và nhận được IP trả về từ DNS là `62.173.142.148`, các gói tin sau đó cho thấy hai máy đã thực hiện việc bắt tay ba bước. Từ đó ta có thể kết luận attacker đã dùng IP `62.173.142.148` tức là trang web `portfolio.serveirc.com` để thực thi việc khởi tạo truy cập tới máy nạn nhân.

![image](https://hackmd.io/_uploads/rJRwrpMYZl.png)

> Flag: 62.173.142.148


**Q2: What is the name of the malicious file used for initial access?**

Attacker thường sẽ thực thi một file mã độc để khởi tạo truy cập tới máy nạn nhân, ta cần xác định ra file mã độc đó là gì để có thể phân tích hành vi sau này.

Phân tích gói tin PCAP mình thấy có một gói tin thể hiện người dùng sử dụng chức năng login của trang web bằng cách truy cập vào URI `/login.php` trong trường hợp là nạn nhân bị tấn công bởi trang web kia thì file `login.php` là rất khả nghi nên mình sẽ trích xuất file đó ra để phân tích thêm. 
Chọn `File -> Export Objects -> HTTP` mình nhận thấy file login có size rất lớn khoảng **5MB** mà thông thường file `login.php` chỉ khoảng **1MB** đổ lại.
![image](https://hackmd.io/_uploads/HkkoHRGKWe.png)

Chọn save, lưu lại và mình nhận được một file `javascript` giả mạo file `php` 
![image](https://hackmd.io/_uploads/Skq1IRGtbe.png)

Nội dung thì bị obfuscate

![image](https://hackmd.io/_uploads/rywWUCMKZg.png)

Mình de-obfuscate thì được nội dung như sau

![image](https://hackmd.io/_uploads/Sk2lPCztbe.png)

Cụ thể, file chứa các lệnh để tải xuống một tệp khác, có tên là Resources.dll, từ một miền (soundata.top) rồi thực thi tệp đó bằng rundll32.exe, một file hệ thống hợp pháp thường bị lạm dụng để thực thi phần mềm độc hại. Tập lệnh cũng tự xóa sau khi thực thi, một kỹ thuật chống pháp y được thiết kế để cản trở việc phân tích. Để lấy tài nguyên yêu cầu từ máy chủ của kẻ tấn công, mình cần kiểm tra luồng HTTP phân phát tệp login.php.

Kiểm tra gói tin chứa file `login.php` mình thấy tên file javascript gốc là `allegato_708.js`

![image](https://hackmd.io/_uploads/rki-uRGtZe.png)


> Flag: allegato_708.js



**Q3: What is the SHA-256 hash of the malicious file used for initial access?**

Xác định mã hash SHA-256 của file độc hại được dùng để khởi tạo truy cập, việc này sẽ giúp ta thu thập được thông tin tình báo từ những vụ tấn công trước đó có dùng file độc hại này.

Dùng lệnh `shs256sum` để tạo hash file `login.php` gốc ta nhận được mã hash
`SHA-256:` `847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268`

![image](https://hackmd.io/_uploads/rJFLFCMYZg.png)

Tra cứu mã hash này trên virustotal ta biết được đây là malware loại **trojan, downloader, phishing**

![image](https://hackmd.io/_uploads/SkZy50GK-g.png)


Malware này thực hiện hành vi Command and Control bằng kỹ thuật **T1071** giao tiếp qua lớp ứng dụng tới một website để trà trộn lưu lượng với các lưu lượng có sẵn của người bình thường để tránh bị phát hiện bởi **IDS/IPS**
![image](https://hackmd.io/_uploads/B1f-gbEKZx.png)

![image](https://hackmd.io/_uploads/B1ZaeZEYZe.png)

> Flag: 847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268

**Q4: Which process was used to execute the malicious file?**

Khi đã biết được file mã độc rồi ta cần xác định xem ai/tiến trình nào đã thực thi file đó để có thể hiểu được rõ hơn hành vi của attacker. File mã độc được viết bằng `JavaScript` cho nên mình sẽ tìm kiếm những tiến trình có sẵn của Windows chuyên để thực thi các file `.js`.

Qua tra cứu mình biết được tiến trình đó là **Windows Script Host (WSH)**.
![image](https://hackmd.io/_uploads/SyonZbEYZx.png)

WSH có hai cách để chạy: **WScript** hiển thị thông báo qua **hộp thoại (cửa sổ pop-up)**, còn **CScript** hiển thị dữ liệu dạng **văn bản trong dòng lệnh (CMD)**.

![image](https://hackmd.io/_uploads/r1-zMb4KWg.png)

Cụ thể malware sẽ dùng **WScript.exe** để thực thi file `js` trên môi trường đồ hoạ có thể là tránh các tool quét ra được các tiến trình lạ chạy qua Command Prompt.

![image](https://hackmd.io/_uploads/rk_7VZNKbl.png)

Qua tra cứu trên MITRE mình thấy có technique có nói về hành vi này

![image](https://hackmd.io/_uploads/BJTtB-4Y-l.png)

> Flag: WScript

**Q5: What is the file extension of the second malicious file utilized by the attacker?**

Ngoài file JavaScript giả mạo `login.php` kia thì còn có file độc hại nào khác được attacker sử dụng nữa không.
Qua phân tích file `.js` sau khi deobfuscate thì mình thấy có một hành động tải thêm một file `resources.dll` nữa. Do đó có thể kết luận loại file đó là `.dll`


![image](https://hackmd.io/_uploads/SyV6L-4t-x.png)

> Flag: .dll


**Q6: What is the MD5 hash of the second malicious file?**

Để tính ra hash MD5 của file `dll` mình tiến hành trích xuất file bằng cách chọn `File -> Export Objects -> HTTP` chọn file `resources.dll` và chọn save. Sau đó dùng lệnh `md5sum` để tính hash mình thu được hash MD5: `e758e07113016aca55d9eda2b0ffeebe`

![image](https://hackmd.io/_uploads/BJV4_-4t-g.png)

Tra cứu trên VirusTotal mình biết được đây là Malware có tag là: MALWARE, STEALER, PHISHING, BANKER, TROJAN, ADWARE, EVADER

![image](https://hackmd.io/_uploads/BJQqpWNFWl.png)

Tra thêm các report thì mình biết được đây chính là malware có tên DanaBot-Trojan ngân hàng tiên tiến được thiết kế để đánh cắp thông tin tài chính từ nạn nhân.

![image](https://hackmd.io/_uploads/By-DRZNYWg.png)


Qua tim hiểu thì mình thấy được malware này thực hiện các kỹ thuật key-logging **T1056.001**, tự động thu thập thông tin ở ứng dụng Mail **T1119** để thu thập thông tin nhắm chiếm đoạt tài khoản ngân hành của nạn nhân.
![image](https://hackmd.io/_uploads/BJJQgM4tWe.png)
