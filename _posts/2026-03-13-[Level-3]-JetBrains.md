---
title: '[Level-3]-JetBrains'
date: 2026-03-13

---

# Lab Report - JetBrains
**DatHN5 - SO3 - FSAS**
---


Analyze network traffic using Wireshark to identify web server exploitation, extract attacker IOCs and persistence mechanisms, and map attack techniques to MITRE ATT&CK. 

**Category**: Network Forensics 
**Tactics**: Initial Access Execution Command and Control 
**Tools**: Wireshark NetworkMiner Brim

#### Scenario
During a recent security incident, an attacker successfully exploited a vulnerability in our web server, allowing them to upload webshells and gain full control over the system. The attacker utilized the compromised web server as a launch point for further malicious activities, including data manipulation. 

As part of the investigation, You are provided with a packet capture (PCAP) of the network traffic during the attack to piece together the attack timeline and identify the methods used by the attacker. The goal is to determine the initial entry point, the attacker's tools and techniques, and the compromise's extent.

### Write up

#### Q1 Identifying the attacker's IP address helps trace the source and stop further attacks. What is the attacker's IP address?


Tình huống là attacker đã tấn công vào web server và upload webshell và chiếm được full quyền quản trị. Và để tìm được IP của máy tấn công tới web server thì mình lọc ra các gói tin `HTTP` để thu hẹp được những IP đã kết nối tới web server.

![image](https://hackmd.io/_uploads/SkP7DqCKbg.png)

Tuy nhiên kết quả thu về vẫn còn rất lớn và rối. 
Vậy nên mình lọc sâu hơn nữa, do là attacker đã có hành vi là upload webshell cho nên mình lọc ra những gói tin mà có nội dung liên quan tới việc attacker upload file qua filer search sau `http contains "upload"`

![image](https://hackmd.io/_uploads/Skwqd90F-l.png)

Ở đây thì mình nhận được kết quả là các response từ server đối với các request có thông tin liên quan tới cụm `upload`

Mình follow theo time của gói tin có info với code 200 và (text/html) để trace xem gói tin trước đó mà IP `23.158.56.196` gửi tới IP `172.31.25.119` là gì.

![image](https://hackmd.io/_uploads/H1Cpu9AF-e.png)

Sau khi trace lại các gói tin trước thì mình thấy có 3 gói tin đáng chú ý đầu tiên là gói tin với thông tin IP `23.158.56.196` vào trang `/admin/pluginUpload` để upload một file `zip` có tên `NSt8bHTg.zip` lên

![image](https://hackmd.io/_uploads/BJONqcAFbl.png)

Sau đó mình có trace thêm các gói tin liên quan tới IP `23.158.56.196` để xem có hành vi nào đang ngờ hay không thì thu được thông tin sau. Sau khi upload thành công thì IP kia liên tục sử dụng tới file `.jsp` bên trong để thực hiện hành vi command injection như `cmd = ls` để thu thập thông tin hệ thống.

![image](https://hackmd.io/_uploads/SJiQocAKbx.png)

![image](https://hackmd.io/_uploads/SkNO25CYWe.png)


>Flag: 23.158.56.196

#### Q2 To identify potential vulnerability exploitation, what version of our web server service is running?

Để tra được version của web server thì mình quyết định filter các gói tin http có thông tin qua search filter sau `http.request && ip.addr==23.158.56.196` 

![image](https://hackmd.io/_uploads/SkZxcV89Zl.png)


Thường khi lần đầu vào web thì ta hay đi vào trang welcome mà ở trang đó sẽ có thông tin về web server này đang dùng apache/nginx/khác.

![image](https://hackmd.io/_uploads/SJyFVVU5Wl.png)

Chọn xem HTTP Stream gói tin có path là `login.html` mình thu được thông tin quan trọng server của nạn nhân đang dùng của bên phân phối TeamCity thuộc JetBrain để deploy.

![image](https://hackmd.io/_uploads/B1lruEL5Wg.png)



Tiếp tục tra cứu kết quả trả về mình thấy có hai request từ IP attacker tới web server là `/hax?jsp=/app/rest/server;.jsp`, sau khi follow HTTP Stream thì mình có thấy được server version bên trong.

![image](https://hackmd.io/_uploads/HybhWi0Ybe.png)

Bên cạnh đó khi tìm hiểu xem request `/hax?jsp=/app/rest/server;.jsp` có ý nghĩa gì mình tìm được kết quả là đây là câu lệnh để bypass auth và mình còn tìm được luôn CVE đi kèm cùng với IOC chi tiết.

[IOC](https://github.com/Stuub/RCity-CVE-2024-27198/)

[CVE-Report](https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/)


`/hax` request tới tài nguyên không tồn tại trên server để trigger code 404, để có thể được chuyển sang hướng xử lý lỗi đặc biệt của TeamCity và đó hay là các trang .jsp (JavaSever Page)

`?jsp=/app/rest/server` nhờ query `jsp` để chuyển hướng sang endpoint thực cần khai thác thông tin ở đây là

`;.jsp` 
- `.jsp` là để vượt qua các kiểm tra kiểu “chỉ cho phép forward/include tới JSP” (ví dụ check endsWith(".jsp") hoặc regex). Nó làm đường dẫn trông “hợp lệ như JSP”.
- `;` là lợi dụng cơ chế xử lý của server, trong  Java Servlet specification, dấu ; trong URL được gọi là path parameter hoặc matrix parameter. Các phần sau dấu `;` sẽ bị strip đi do đó phần path trước nó sẽ được giữ nguyên

>Flag: 2023.11.3

#### Q3 After identifying the version of our web server service, what CVE number corresponds to the vulnerability the attacker exploited?

Mình đã biết rằng server này dùng Teamcity ver 2023.11.3 build 147512 để deploy, và từ thông tin tra cứu được ở câu trước mình biết rằng CVE mà web server này bị attacker lợi dụng để khai thác đó chính là `CVE-2024-27198`

[CVE-Report](https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/)

CVE này mô tả rằng attacker có thể lợi dụng các lỗ hổng để bypass qua các bước xác thực bắt buộc để thực hiện các hành vi mà chỉ admin hay người dùng xác thực mới làm được.

![image](https://hackmd.io/_uploads/ByDGrHI9Wg.png)

![image](https://hackmd.io/_uploads/HkRvHBL5We.png)

![image](https://hackmd.io/_uploads/HyIYrBU9We.png)

Attacker còn tận dụng lỗi này để tạo account mới với role là SYSTEM_ADMIN

![image](https://hackmd.io/_uploads/SkBP8SIcbe.png)

![image](https://hackmd.io/_uploads/Hk5YIBI9Wg.png)

Thông tin reponse từ server cho thấy account đã tạo thành công với `id` = 2

![image](https://hackmd.io/_uploads/BJBDxO89bx.png)



#### Q4 The attacker exploited the vulnerability to create a user account. What credentials did he set up?

Như đã phân tích ở câu trên thì account mới mà attacker đã tạo đó là

![image](https://hackmd.io/_uploads/SyhCLSUqWg.png)

`/username:c91oyemw` `/password:CL5vzdwLuK`

>Flag: c91oyemw:CL5vzdwLuK

#### Q5 The attacker uploaded a webshell to ensure his access to the system. What is the name of the file that the attacker uploaded?

Để biết attacker đã upload file gì mình follow theo luồng của attacker thì thấy có 1 request với thông tin http method là POST và có đường dẫn tới trang `/admin/pluginUpload.html` của web server để upload 1 file zip có tên là `NSt8bHTg.zip`

![image](https://hackmd.io/_uploads/Bkql7d8cbx.png)


>Flag: NSt8bHTg.zip

#### Q6 When did the attacker execute their first command via the web shell?

Sau khi attackr upload file zip lên, server đã tự giải nén file và đưa vào thư mục `/plugins`, sau đo mình thấy attacker có truy cập vào thư mục plugin để thực thi file `.jsp` - **JavaServer Pages** có chức năng tạo nội dung web động qua việc chạy code Java phía server và render kết quả dưới dạng JSON/HTML cho trình duyệt.

Ta có thể thấy được attacker đã thực hiện Command Injection đầu tiên vào là `"cmd" = "ls"` 

![image](https://hackmd.io/_uploads/rJkylnAY-e.png)

![image](https://hackmd.io/_uploads/Hk8cM3CK-e.png)

![image](https://hackmd.io/_uploads/ByIlN_Ic-e.png)


>Flag: 2024-06-30 08:03

#### Q7 The attacker tampered with a text file that contained the credentials of the admin user of the webserver. What new username and password did the attacker write in the file?

Để xem attacker đã viết tài khoản và mật khẩu mới nào vào file mình tìm tới các gói tin có liên quan tới file `.jsp` do attacker dùng file đó để thực hiện Command Injection.

![image](https://hackmd.io/_uploads/r1gWBhAFZl.png)

Mình tìm được gói tin thể hiện command mà attacker đã dùng để viết lại file là

`bash -c 'echo "username:a1l4m,password:youarecompromised" > /tmp/Creds.txt'`

>Flag: a1l4n:youarecompromised

#### Q8 What is the MITRE Technique ID for the attacker's action in the previous question (#### Q7) when tampering with the text file?

Hành vi của attacker làm là sửa nội dung file có sẵn được lưu tĩnh tại vị trí cố định đối chiếu với MITRE mình tìm được technique là [T1565](https://attack.mitre.org/techniques/T1565/) cụ thể là sub technique  [T1565.001](https://attack.mitre.org/techniques/T1565/001/)

![image](https://hackmd.io/_uploads/HJOgocyqWx.png)

>Flag: T1565.001

#### Q9 The attacker tried to escape from the container but he didn’t succeed, What is the command that he used for that?

![image](https://hackmd.io/_uploads/B1fiO3Rt-e.png)

![image](https://hackmd.io/_uploads/B1e6dnRKbe.png)

![image](https://hackmd.io/_uploads/BJD0_3CFWl.png)


Qua xem xét các gói tin mình thấy attacker đã chạy container ubuntu với `--privileged` để có thể gỡ bỏ phần lơn cơ chế bảo vệ của container. Sau đó chạy thêm hai lệnh nữa để thoát ra khỏi container, trong đó có một lệnh đã không thành công do không có đủ quyền là 
`docker run --rm -it -v /:/host ubuntu chroot /host` 
sau đó để lấy được quyền root để attacker đã chạy 
`docker run -v /var/run/docker.sock:/var/run/docker.sock -it ubuntu`

Vậy command mà attacker chạy để thoát khỏi container nhưng gặp lỗi do không có đủ quyền đó là 
`docker run --rm -it -v /:/host ubuntu chroot /host`

Để lấy quyền cao hơn attacker đã mount docker socket `/var/run/docker.sock` vào trong docker để có được quyền điều khiển Docker daemon trên host, do cái socket kia chính là cầu nối để giao tiếp giữa docker client và docker daemon. Từ đó attacker có thể ở trong container nhưng có toàn quyền đối với host - đây là kiểu leo thang đặc quyền qua docker không được cấu hình kỹ.

>Flag: docker run --rm -it -v /:/host ubuntu chroot /host