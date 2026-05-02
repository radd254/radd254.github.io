---
title: '[Level-3]-IcedID_Report'
date: 2026-03-12

---

# Lab Report - IcedID 
**DatHN5 - SO3 - FSAS**
<p align="center"> Lab Report - IcedID </p>

Scenario
A cyber threat group was identified for initiating widespread phishing campaigns to distribute further malicious payloads. The most frequently encountered payloads were IcedID. You have been given a hash of an IcedID sample to analyze and monitor the activities of this advanced persistent threat (APT) group.

### Write up

Ở bài này ta được yêu cầu điều tra phần mềm độc hại IcedID bằng VirusTotal và các nền tảng thông tin đe dọa (malpedia, XTria, ANY.RUN) để xác định IOC, nhóm tội phạm mạng liên quan và cơ chế thực thi. 
Một nhóm tấn công đã được phát hiện thực hiện các chiến dịch phishing quy mô lớn, nhằm phân phối các payload độc hại, trong đó IcedID xuất hiện thường xuyên nhất. Ta nhận được hash của một mẫu IcedID để phân tích và giám sát hoạt động của nhóm APT này.

 ![image](https://hackmd.io/_uploads/HkJm7dGtWx.png)

Hash: 191eda0c539d284b29efe556abb05cd75a9077a0
Trên đây là đoạn hash ta nhận được, ta sẽ tra cứu trên trang VirusTotal để phân tích sâu thêm. Khi tìm hiểu trên VirusTotal ta có thể biết tổng quan rằng đây là malware thuộc họ IcedID, chủ yếu lây nhiễm qua file Excel trên máy tính Windows, sử dụng kỹ thuật tránh phát hiện và có thể kết nối ra ngoài để tải hoặc giao tiếp với C2, tiềm ẩn nguy cơ lây nhiễm các payload khác và đánh cắp dữ liệu.

 ![image](https://hackmd.io/_uploads/BkoX7uMFZg.png)

### Q1: What is the name of the file associated with the given hash?
Kiểm tra tab Detail mục Names ta thấy được malware này đã cuất hiện với ít nhất 4 cái tên khác nhau và cái tên mà ta cần tìm là cái tên đầu tiên của malware đó chính là

-	document-1982481273.xlsm

 ![image](https://hackmd.io/_uploads/SyN4Q_ztWx.png)

> Flag: document-1982481273.xlsm

### Q2: Can you identify the filename of the GIF file that was deployed?
Tên file GIF được malware sử dụng để ẩn mình là gì.
Trong tab Relations mục Contacted URLs ta có thể thấy malware đang cố tải thêm các mảnh payload nữa để phục vụ việc xâm nhập tên của file được tải về là 3003.gif

 ![image](https://hackmd.io/_uploads/S1RE7dGY-e.png)

> Flag: 3003.gif

### Q3: How many domains does the malware look to download the additional payload file in Q2?
Có bao nhiêu domain mà malware cố gắng kết nối để tải thêm payload, như đã tìm được trên Q2 ta có thể thấy rằng có 5 domain mà malware đã gửi lệnh để kết nối tới và tải file.

 ![image](https://hackmd.io/_uploads/HkYBX_fKbl.png)

> Flag: 5

### Q4: From the domains mentioned in Q3, a DNS registrar was predominantly used by the threat actor to host their harmful content, enabling the malware's functionality. Can you specify the Registrar INC?
Từ những domain tìm được ở Q3, xác định ra tên nhà cung cấp Domain mà malware dùng để host các file nội dung độc hại phục vụ các chức năng của nó. 
Dựa vào những gì đã tìm được ta đối chiếu với mục Contacted Domains để tìm nhà cung cấp. Trong 5 domain thì chỉ có 1 domain xác định được nhà cung cấp đó là tajushariya.com của NameCheap, Inc.  các domain còn lại thì 1 là dùng domain thứ cấp free hoặc là không xác định được rõ ràng.

 ![image](https://hackmd.io/_uploads/rkHLX_zKZl.png)

> Flag: NameCheap

### Q5: Could you specify the threat actor linked to the sample provided? 
Xác định ra tên của threat actor liên quan tới malware kia. Tức là tìm ra những chủ thể đã sửa dụng malware kia để thực hiện hành vi vi phạm.
Dựa vào hint ta sẽ tìm nó trên bộ framework là Mitre ATT&CK để biết thêm các thông tin quan trọng khác. Ở đây ta biết cơ bản rằng malware IcedID đã được phát hiện từ 2017

 ![image](https://hackmd.io/_uploads/rkiU7uMFbx.png)

Và có 2 Group đã sử dụng malware này phục việc tấn công bảo mật

![image](https://hackmd.io/_uploads/Hy8DX_ft-l.png)
 
Ở đây group TA578 thì không hẳn là group lớn có tên cụ thể

 ![image](https://hackmd.io/_uploads/B1wumOzFWg.png)

Còn group TA551 thì có đầy đủ thông tin hơn về tên tổ chức trong đó tên chính thức là GOLD CABIN và Shathak là tên phụ

![image](https://hackmd.io/_uploads/rJMYXOfKZl.png)

![image](https://hackmd.io/_uploads/H18Ym_zYWg.png)

 
 > Flag: GOLD CABIN

### Q6: In the Execution phase, what function does the malware employ to fetch extra payloads onto the system? 
Hint
Dựa vào hint được cho ta sẽ đi tìm kiếm các report phổ biến về malware kia, và ở trong tab Community của VirusTotal là nơi tổng hợp khá đầy đủ các thông tin liên quan tới các report / analysis về malware này

 ![image](https://hackmd.io/_uploads/BJH5Q_fF-l.png)

Ở đây ta sẽ nghiên cứu report mới nhất của Tria.ge 
Ta sẽ đi tìm các lệnh call API được dùng bởi malware kia và trong mục Malware Config có thể thấy được 5 lệnh kết nối tới 5 domain để tải các file GIF đã được đề cập ở câu hỏi bên trên và có thể thấy được tên Function được dùng để tải file là URLDownloadToFileA

 ![image](https://hackmd.io/_uploads/rycqmuGYZe.png)

> Flag: URLDownloadToFileA
