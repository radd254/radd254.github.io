---
title: '[Level-4]-AzureHunt'
date: 2026-03-21

---

# Lab Report - AzureHunt
**DatHN5 - SO3 - FSAS**
---

Correlate Azure AD, Activity, and Blob Storage logs in Elastic Stack to reconstruct an attack timeline, identifying initial access, lateral movement, persistence, and data exfiltration. 

**Category**: Cloud Forensics 
**Tactics**: Persistence Privilege Escalation Collection 
**Tool**: ELK

#### Scenario
A finance company's Azure environment has flagged multiple failed login attempts from an unfamiliar geographic location, followed by a successful authentication. Shortly after, logs indicate access to sensitive Blob Storage files and a virtual machine start action. Investigate authentication logs, storage access patterns, and VM activity to determine the scope of the compromise.


#### Q1 As a US-based company, the security team has observed significant suspicious activity from an unusual country. What is the name of the country from which the attack originated?

![image](https://hackmd.io/_uploads/ryf8joeh-e.png)

![image](https://hackmd.io/_uploads/ByiYiien-l.png)


---


![image](https://hackmd.io/_uploads/rkvjxDRqbg.png)

![image](https://hackmd.io/_uploads/B1SVAU09Zx.png)


US - Dữ liệu thu được đang khá nhiễu chưa kết luận được

![image](https://hackmd.io/_uploads/BJei60e3Zg.png)

France - đây là ip của MS Corp chính chủ tại Pháp -> bỏ khỏi diện nghi vấn - [Source](https://db-ip.com/all/20.19.30)

![image](https://hackmd.io/_uploads/HJlAp0x2Ze.png)

![image](https://hackmd.io/_uploads/HJ4XzvAq-l.png)


Germany - Không có các trường hợp như sai password nhưng lại có vấn đề là có 1 IP thực ra không phải từ Đức là mà ở chỗ khác

![image](https://hackmd.io/_uploads/HkLGsRgh-x.png)

![Screenshot 2026-04-06 140034](https://hackmd.io/_uploads/ryy1aAx3Zx.png)

![Screenshot 2026-04-06 140056](https://hackmd.io/_uploads/HyNyTAenWl.png)

![Screenshot 2026-04-06 140122](https://hackmd.io/_uploads/HkdJpAl3Ze.png)

![Screenshot 2026-04-06 140208](https://hackmd.io/_uploads/S1nyT0ehWx.png)

![image](https://hackmd.io/_uploads/B1XJHDCqWg.png)

Ít lượt truy cập cộng với địa chỉ IP bất thường kết luận nơi cuộc tấn công khởi nguồn là từ Đức. Và ba account `alice, it.admin1, it_support` nằm trong diện nghi nghờ là đã bị compromise

> Germany



#### Q2 To establish an accurate incident timeline, what is the timestamp of the initial activity originating from the country?

Thời điểm của hành vi đầu tiên xuất phát từ nước Đức là vào 2023-10-05 15:09

![image](https://hackmd.io/_uploads/BkDNRAehbx.png)

> 2023-10-05 15:09

#### Q3 To assess the scope of compromise, we must determine the attacker's entry point. What is the display name of the compromised user account?

Theo scenario thì trước khi thành công login attacker đã bị fail vài lần trước đó và mình sẽ tìm xem những hành vi fail login gần nhau nhiều lần thì nhận được kết quả là account `alice` và `it.admin1` có dấu hiệu fail login nhiều lần mà thời gian lại gần nhau.

Và ở trường mô tả là `Due to a configuration change made by your administrator, or because you moved to a new location, you must enroll in multi-factor authentication to access the tenant.` tức là có khả năng cao là có 2 người ở hai nơi cách xa nhau cùng login vào 

![img](https://hackmd.io/_uploads/HJT-fJWhZg.png)

![image](https://hackmd.io/_uploads/BJd3xJWhbx.png)

Duy chỉ có account `it_support` là không thấy có lần fail login nào -> bỏ khỏi diện nghi vấn là bị compromise

![image](https://hackmd.io/_uploads/HysrfyWhZl.png)


alice

![image](https://hackmd.io/_uploads/SJkqP1WnZe.png)


it.admin1

![image](https://hackmd.io/_uploads/BJYzYkb3Zg.png)

![image](https://hackmd.io/_uploads/HkE6VcX3-e.png)

Cả hai account `alice` và `it.admin1` đều bị compromise nhưng dựa theo timeline đăng nhập tại địa điểm là nước Đức nên kết luận rằng account `alice` bị chiếm trước.

> alice


#### Q4 To gain insights into the attacker's tactics and enumeration strategy, what is the name of the script file the attacker accessed within blob storage?

Mục tiêu là tìm ra cái script mà attacker truy cập nằm trong blob storage.
Mình search `blob` lên thanh tìm kiếm và bắt đầu dò vài mẫu log thì thu được thông tin sau

Có 1 trường đánh dấu log của blob là `azure-eventhub.eventhub` với data là `bloblogs`, cùng với các thônng tin liên quan tới các hành vi truy cập như `operationName`, `azure.eventhub.uri`, `azure.resource.id`, `azure.resource.id`

![image](https://hackmd.io/_uploads/rJSXTYmn-l.png)

![image](https://hackmd.io/_uploads/rkwuTFm3Wl.png)

![image](https://hackmd.io/_uploads/r1AmRF72Wg.png)

Mình tạo bảng từ các field trên để quan sát dễ hơn, thì thấy rằng có 1  script duy nhất với tên là `service-config.ps1` liên tục được truy cập tới để khai thác thông tin của Blob storage

![image](https://hackmd.io/_uploads/rkn_RKXhbl.png)

> service-config.ps1

#### Q5 For a detailed analysis of the attacker's actions, what is the name of the storage account housing the script file?

Dựa vao thông tin từ document của MS, mình thấy rằng storage account sẽ nằm ngay trong cái URI mà mình tìm được bên trên

![image](https://hackmd.io/_uploads/SylVkcX3be.png)

![image](https://hackmd.io/_uploads/rkn_RKXhbl.png)

> cactusstorage2023


#### Q6 Tracing the attacker's movements across our infrastructure, what is the User Principal Name (UPN) of the second user account the attacker compromised?

Như đã phân tích từ trước có hai account bị compromise là `alice` và `it.admin` và `alice` bị đã bị chiếm trước

Trong log có field `user_principal_name` được extract sẵn nên mình tìm được luôn

![image](https://hackmd.io/_uploads/H1MH8cm2Zl.png)

> it.admin1@cybercactus.onmicrosoft.com


#### Q7 Analyzing the attacker's impact on our environment, what is the name of the Virtual Machine (VM) the attacker started?

Mình search luôn lên thanh search là `VIRTUALMACHINES` thì bắt được một số event liên quan, phân tích thành phần các field trong đó

![image](https://hackmd.io/_uploads/r1Ey-uohbl.png)

![image](https://hackmd.io/_uploads/S1GHtqQhZx.png)

![image](https://hackmd.io/_uploads/B1r_Y57nbx.png)

Lập bảng để xem có các VM nào được khởi chạy thì mình chỉ thấy có 1 VM duy nhất được chạy đó là VM có tên `DEV01VM`

![image](https://hackmd.io/_uploads/rkS-9cXnbe.png)

> DEV01VM

#### Q8 To assess the potential data exposure, what is the name of the database exported?

Mình cũng search thẳng keyword `export` do không rõ fielname liên quan thì có bắt được 2 event
Qua phân tích thì thấy rằng có 1 DB tên là `CUSTOMERDATADB` đang bị export ra ngoài

![image](https://hackmd.io/_uploads/HkbKLsm2Zg.png)

![image](https://hackmd.io/_uploads/S1p1wsmnWx.png)

```!
azure.activitylogs.operation_name    MICROSOFT.SQL/SERVERS/DATABASES/EXPORT/ACTION

azure.resource.name                  CACTUSDBSERVER/DATABASES/CUSTOMERDATADB
```

> CUSTOMERDATADB

#### Q9 In your pursuit of uncovering persistence techniques, what is the display name associated with the user account you have discovered?

Nói tới persistence thì việc mình nghĩ tới đầu tiên là có 1 account mới được thêm vào hệ thống nên mình search thử xem có thông tin nào có liên quan tới việc tạo/thêm accoutn không. 
Mình search thử `user creation` và `user add` thì thấy có 1 event có data fiel là Add user, phân tích event đó thì thấy rằng account `It Support` là account do attacker tạo để duy trì truy cập tới hệ thống.

![image](https://hackmd.io/_uploads/BkGZGOonZg.png)

![image](https://hackmd.io/_uploads/Hy0SlDihbe.png)

![image](https://hackmd.io/_uploads/HkbDeDshWe.png)

![image](https://hackmd.io/_uploads/ByR_gwihbl.png)

![image](https://hackmd.io/_uploads/S119ePi2be.png)

> IT Support


#### Q10 The attacker utilized a compromised account to assign a new role. What role was granted?

Ban đầu mình thử search với keywork `role` để xem các evvent liên quan nhưng kết quả không cung cấp được gì nhiều, ngoại trừ mình biết được có fieldname là `azure.activitylogs.identity.authorization.evidence.role` có thể là fiel lưu role thực sự.

![image](https://hackmd.io/_uploads/H1NazwsnZg.png)

![image](https://hackmd.io/_uploads/B1tizPihbl.png)

Mình có tìm document liên quan thì thấy được các fieldname liên quan tới việc gán role

![image](https://hackmd.io/_uploads/H12kNOo2Wl.png)

![image](https://hackmd.io/_uploads/B1oiN_onZl.png)

![image](https://hackmd.io/_uploads/HyksE_s2Zg.png)



#### Q11 For a comprehensive timeline and understanding of the breach progression, What is the timestamp of the first successful login recorded for this user account?

![image](https://hackmd.io/_uploads/BkOONPjnZx.png)

Oct 6, 2023 @ 07:30:43.113

> 2023-10-06 07:30


