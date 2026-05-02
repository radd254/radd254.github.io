---
title: '[Level-4]-Web_Investigation'
date: 2026-03-23

---

# Lab Report - Web Investigation
**DatHN5 - SO3 - FSAS**
---

Examine network traffic with Wireshark to investigate web server compromise, identify S### QL injection, extract attacker credentials, and detect uploaded malware. 

**Category**: Network Forensics 
**Tactics**: Initial Access, Persistence, Command and Control 
**Tools**: Wireshark Network Miner

### Scenario

You are a cybersecurity analyst working in the Security Operations Center (SOC) of BookWorld, an expansive online bookstore renowned for its vast selection of literature. BookWorld prides itself on providing a seamless and secure shopping experience for book enthusiasts around the globe. Recently, you've been tasked with reinforcing the company's cybersecurity posture, monitoring network traffic, and ensuring that the digital environment remains safe from threats. 
Late one evening, an automated alert is triggered by an unusual spike in database queries and server resource usage, indicating potential malicious activity. This anomaly raises concerns about the integrity of BookWorld's customer data and internal systems, prompting an immediate and thorough investigation. 
As the lead analyst in this case, you are required to analyze the network traffic to uncover the nature of the suspicious activity. Your objectives include identifying the attack vector, assessing the scope of any potential data breach, and determining if the attacker gained further access to BookWorld's internal systems.

## Write up

### Q1 By knowing the attacker's IP, we can analyze all logs and actions related to that IP and determine the extent of the attack, the duration of the attack, and the techniques used. Can you provide the attacker's IP?

Để tra ra được IP của attacker mình cần xác định rõ các IP xuất hiện trong file PCAP này.

Mình chọn `Statistics -> Conversations` để xem có IP nào giao tiếp với IP nào.
![image](https://hackmd.io/_uploads/B1P3AZpFZl.png)
Mình nhận thấy có IP `111.224.250.131` giao tiếp với IP `73.124.22.98` rất nhiều thông tin nên mình sẽ đi sâu xem IP này có phải IP của attacker không.

Mình lọc các gói tin liên quan tới IP `111.224.250.131` bằng filter sau
`ip.src==111.224.250.131 or ip.dst==111.224.250.131`
![image](https://hackmd.io/_uploads/Hy4WgM6Fbe.png)

Kết quả nhận được là IP `111.224.250.131` đã kết nối thành công bắt tay ba bước với IP `73.124.22.98`, và truy cập tới web server nội bộ.

Lọc sâu hơn để tìm các gói tin `HTTP` thì mình thấy rằng IP `111.224.250.131` đang thực hiện các lệnh `SQLi` tới web server `73.124.22.98` nên mình kết luận rằng `111.224.250.131` là IP của attacker.
`(ip.src==111.224.250.131 or ip.dst==111.224.250.131) && http.request`
![image](https://hackmd.io/_uploads/B1UAbfatZl.png)

> Flag: `111.224.250.131`

---
### Q2 If the geographical origin of an IP address is known to be from a region that has no business or expected traffic with our network, this can be an indicator of a targeted attack. Can you determine the origin city of the attacker?

Để tìm ra vị trí địa lý của IP `111.224.250.131` mình dùng web [Link](https://www.geolocation.com/?ip=111.224.250.131#ipresult) để tra 

![image](https://hackmd.io/_uploads/SkvCzM6Y-g.png)

Kết quả trả về là thành phố `Shijiazhuang`

> Flag: Shijiazhuang

---
### Q3 Identifying the exploited script allows security teams to understand exactly which vulnerability was used in the attack. This knowledge is critical for finding the appropriate patch or workaround to close the security gap and prevent future exploitation. Can you provide the vulnerable PHP script name?



Để xác định được file `.php` script có chứa lỗi khai thác mà attacker dùng để expoit mình vẫn dùng filter từ câu 1, mình nhận thấy là attacker đã tận dụng script `search.php` có thể chứa lỗi do dev không lọc để khai thác `SQLi`

![image](https://hackmd.io/_uploads/r1e_Xf6YWx.png)

> Flag: `search.php`

---
### Q4 Establishing the timeline of an attack, starting from the initial exploitation attempt, what is the complete request URI of the first S### QLi attempt by the attacker?

Note: Decode the Value.

Câu lệnh SQLi đầu tiên là `/search.php?search=book%20and%201=1;%20--%20-`
![image](https://hackmd.io/_uploads/ByuXLzTFZg.png)

Decode ra thì được URI sau: `/search.php?search=book and 1=1; -- -`

> Flag: `/search.php?search=book and 1=1; -- -`
---
### Q5 Can you provide the complete request URI that was used to read the web server's available databases?

Note: Decode the Value.

Để tìm ra được URI chính xác dùng để tìm database mình sẽ extract lấy đống URI kia ra ngoài qua cách xuất object HTTP ra rồi mình sẽ phân tích thêm.

Chọn `File -> Export Objects -> HTTP -> Save All`

![image](https://hackmd.io/_uploads/rJDGcfpKbx.png)

Mình được các thư như sau

![image](https://hackmd.io/_uploads/ByuKE4aY-l.png)


Sau đó mình viết vào file txt tên các file chứa kèm SQLi kia để tiện decode

![image](https://hackmd.io/_uploads/SyPUxBciWx.png)

Mình đưa lên cyberchef để decode ra plaintext

![img](https://hackmd.io/_uploads/HkHwxrcsZe.png)

![image](https://hackmd.io/_uploads/Syz9xScoZx.png)

Attacker đã trích xuất dữ liệu từ database nạn nhân qua các query có chứa keyword `CONCAT`

![image](https://hackmd.io/_uploads/H1z6Zr9ibx.png)

`UNION ALL SELECT NULL,` ...: Kết hợp các kết quả tìm kiếm hợp pháp với kết quả từ truy vấn bí mật của attacker. NULL được sử dụng để khớp với số lượng cột mà trang gốc mong đợi.

`CONCAT(0x7178766271, ..., 0x7176706a71)`: Đây là các **marker** Hex được sử dụng để xác định nơi dữ liệu bị đánh cắp bắt đầu và kết thúc trong đầu ra của trang web.

    0x7178766271 = qxvbq (Điểm đánh dấu bắt đầu)
    0x7176706a71 = qvpjq (Điểm đánh dấu cuối)

`JSON_ARRAYAGG(...)`: Hàm này nhóm tất cả các hàng bị đánh cắp thành một chuỗi JSON duy nhất để attacker có thể tải xuống toàn bộ bảng trong một lần.

`CONCAT_WS(0x7a76676a636b, ...)`: kết hợp các trường (như id, username, password) bằng dấu phân cách (0x7a76676a636b = zvgjck).

Các thông tin mà attacker đã lấy được đó là loại Database đang dùng

Các thông tin từ bảng book, customer, admin

Trong đó attacker đã dùng SQLi với query sau để trích xuất thông tin schema của database 

```!
search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -
```

> Flag: 
>
> search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,schema_name)),0x7176706a71) FROM INFORMATION_SCHEMA.SCHEMATA-- -

---
### Q6 Assessing the impact of the breach and data access is crucial, including the potential harm to the organization's reputation. What's the table name containing the website users data?

Ở đây mình phải tìm ra thông tin mà attacker đã lấy được từ database cụ thể là attacker đã lấy được bảng nào trong database mà có chứa thông tin khách hàng.

Trong 1 query SQLi của attacker mình thấy có 1 query dùng để trích xuất các thông tin của customer như address, email, first_name, last_name, phone

```!
search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,address,email,first_name,id,last_name,phone)),0x7176706a71) FROM bookworld_db(1).customers-- -

search.php?search=book' UNION ALL SELECT NULL,CONCAT(0x7178766271,JSON_ARRAYAGG(CONCAT_WS(0x7a76676a636b,address,email,first_name,id,last_name,phone)),0x7176706a71) FROM bookworld_db.customers-- -
```

Kết luận bảng chứa thông tin khách hàng là `customers`

> Flag: `customers`

---
### Q7 The website directories hidden from the public could serve as an unauthorized access point or contain sensitive functionalities not intended for public access. Can you provide the name of the directory discovered by the attacker?

Khi mà nhắc tới các directory ẩn khỏi public thì mình sẽ nghĩ tới chỗ đặt trang quản trị `admin` thế nên mình sẽ lọc ra các gói tin mà attacker đang quét các thư mục liên quan tới cụm `admin`.

Ở đây mình lọc `/admin/` là để tìm tới thư mục luôn bởi file có cụm `admin` khá là nhiều
` ip.addr==111.224.250.131&& http contains "/admin/" `
![image](https://hackmd.io/_uploads/HkFAQrpFWx.png)
Kết quả mình thu được là attacker đã dò ra thư mục admin

Kết luận thư mục đó là `/admin/`

> Flag: `/admin/`

---
### Q8 Knowing which credentials were used allows us to determine the extent of account compromise. What are the credentials used by the attacker for logging in?

Để tìm ra tài khoản và mật khẩu mà attacker đã dùng đăng nhập vào trang admin mình sẽ dò gói tin có method là `POST` tới trang `admin/login.php`.

Mình nhận thấy attacker đã thử 4 lần tài khoản và mật khẩu như sau
![image](https://hackmd.io/_uploads/HyuaLBatbe.png)
![image](https://hackmd.io/_uploads/BkeyvSpFbg.png)
![image](https://hackmd.io/_uploads/HJJlPBptZg.png)
![image](https://hackmd.io/_uploads/r1dxPH6tZe.png)
![image](https://hackmd.io/_uploads/H14ZvrpF-e.png)

Tài khoản và mật khẩu chính xác là `admin:admin123!`

> Flag: `admin:admin123!`

---
### Q9 We need to determine if the attacker gained further access or control of our web server. What's the name of the malicious script uploaded by the attacker?

Phân tích thêm mình thấy ngay sau khi thành công login vào trang admin, attacker đã upload một file `php` lên server có tên là: `NVri2vhp.php`
![image](https://hackmd.io/_uploads/SJ_TDBaYWe.png)

> Flag: NVri2vhp.php