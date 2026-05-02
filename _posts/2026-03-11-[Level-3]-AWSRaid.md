---
title: '[Level-3]-AWSRaid'
date: 2026-03-11

---

# Lab Report - AWSRaid 
**DatHN5 - SO3 - FSAS**
---
Investigate AWS CloudTrail logs using Splunk to identify unauthorized access, analyze configuration changes, and detect persistence mechanisms.

**Category**: Cloud Forensics
**Tactics**: Persistence, Privilege Escalation, Credential Access
**Tool**: Splunk

#### Scenario
Your organization utilizes AWS to host critical data and applications. An incident has been reported that involves unauthorized access to data and potential exfiltration. The security team has detected unusual activities and needs to investigate the incident to determine the scope of the attack.

### Write up

#### Q1 Knowing which user account was compromised is essential for understanding the attacker's initial entry point into the environment. What is the username of the compromised user?

Dùng index=* mình thấy tổng cộng có 4032 event

![image](https://hackmd.io/_uploads/BkdCIZgcbx.png)

Mình sẽ list ra các sourcetype để xem co những loại nào để thu hẹp lại cho đúng với môi trường AWS

Dùng query dưới đây để lọc, mình nhận được kết quả là chỉ có một loại sourcetype duy nhất là aws:cloudtrail, và chỉ có 1 index là aws_cloudtrail

```!
| tstats count as event_count  by index, sourcetype
| sort - event_count
```

![image](https://hackmd.io/_uploads/BJYG4xx9-x.png)

Ở AWS khi người dùng tạo tài khoản thì đó được gọi là `root User`, và thường root user sẽ bắt buộc phải được bảo mật ở mức cao nhất như là mật khẩu phải đáp ứng các điều kiện về độ dài cũng như độ phức tạp và còn phải có xác thực MFA đi kèm. 

Người dùng của một dự án chạy trên AWS thường sẽ được người là quản trị viên của dự án nắm root account tạo ra các tài khoản IAM, loại tài khoản này sẽ được phép truy cập và sử dụng tài nguyên của tài khoản root nhưng sẽ bị hạn chế bởi các policy mà admin setup lên. 

Một root account có thể tạo nhiều IAM account với nhiều mục đích khác nhau để quản lý những thứ khác nhau.

Ở trong bộ log này mình thấy có 2 loại account là IAMUser và AWSService, không thấy có root account nên loại bỏ khả năng rằng root account bị compromise.

![image](https://hackmd.io/_uploads/rJHaPbe9bx.png)

**IAMUser**
-   Là **tài khoản người dùng thật (human user)** trong AWS IAM.
-   Được tạo cho **admin, developer, hoặc người vận hành** để đăng nhập AWS Console hoặc dùng CLI/API.
-   Ví dụ: `alice-admin`, `dev-user`.

**AWSService**
-   Là **tài khoản dịch vụ của AWS (service principal)**.
-   Được **AWS service tự động sử dụng để thực hiện hành động thay mặt bạn**.
-   Ví dụ:
    -   **EC2** gọi API

Một diều nữa là attacker thường chỉ có thể chiếm được IAMUser account chứ không thể/cực khó chiếm được AWSService account bởi nếu chiếm được AWSService account thì ngang với đánh sập AWS luôn rồi. Vậy nên mình sẽ tập trung phân tích các IAMUser account xem các tài khoản này cái nào có dấu hiệu bất thường.

Quan sát một mẫu log mình thấy thông tin lưu loại tài khoản có trong userIdentity.type 

![image](https://hackmd.io/_uploads/SyEGbqM5Wx.png)

Từ đây mình cần xem có bao nhiêu IAMUser account được tạo có trong log này bằng câu lệnh như sau

```!
sourcetype="aws:cloudtrail"
| spath
| search userIdentity.type=IAMUser
| stats count as event_count by userIdentity.userName
| sort - event_count
```
**`sourcetype="aws:cloudtrail"`** 
→ Lọc log **CloudTrail của AWS**.

**`spath`** 
→ Parse dữ liệu **JSON trong log** để trích xuất các field.

**`search userIdentity.type=IAMUser`** 
→ Chỉ lấy **event được thực hiện bởi IAM User (người dùng thật)**.

**`stats count as event_count by userIdentity.userName`** 
→ **Đếm số event của từng IAM user**.


![image](https://hackmd.io/_uploads/BkXiKel5Wx.png)

Thu được các account IAM như sau:

**`admin.john,
helpdesk.luke,
cloudops.ryan,
devops.ethan,
businessanalyst.peter,
dataanalyst.sarah,
marketing.sophia,
appdev.mark,
frontenddev.chris,
sysadmin.mary,
backenddev.lisa,
itmanager.david,
customersupport.adam,
devops.kate,
Cloud.Admin`**

Thường trước khi 1 account bị compromise nó có thể có các hành vi như login bị fail như do sai mật khẩu chẳng hạn vậy nên mình sẽ tìm thông tin có liên quan tới việc login. Mình nhận thấy rằng ở field `eventType` có thông tin liên quan tới việc login là `AwsConsoleSignIn`

![Screenshot 2026-03-14 145340](https://hackmd.io/_uploads/SkTv1iM5Wg.png)

Lọc xem các event có `eventType` là `AwsConsoleSignIn` thấy rằng sẽ có hai trường hợp là `Success` và `Failure`

![image](https://hackmd.io/_uploads/BkuiZjMc-e.png)

Vậy nên mình muốn xem rằng account mà đã login fail như vậy nên dùng query sau để xem 

```!
sourcetype="aws:cloudtrail" userIdentity.type=IAMUser eventType=AwsConsoleSignIn responseElements.ConsoleLogin=Failure
| stats count by userIdentity.userName
| sort - count
```

![image](https://hackmd.io/_uploads/SyY3IiG9Zl.png)


Kết quả là mình thấy rằng account `helpdesk.luke` đã fail 10 lần, để rõ hơn thì mình thêm field time để xem những lần fail này có thực sự khả nghi hay không bằng query sau

```!
sourcetype="aws:cloudtrail" userIdentity.type=IAMUser eventType=AwsConsoleSignIn responseElements.ConsoleLogin=Failure 
| stats count by userIdentity.userName _time
| sort - _time
```

![image](https://hackmd.io/_uploads/B1lFPjfqWx.png)

Mình nhận ra rằng có tới 9 lần fail của acccount `helpdesk.luke` là liên tiếp trong thời gian ngắn chỉ trong 30s, 9 lần đăng nhập fail trong 30s là rất khả nghi bởi các trang login khi ta nhập fail pass thì ta sẽ phải nhập lại pass và pass ở đây là của aws có các ký tự đặc biệt và còn dài nữa.

Ta hiện tại có thể flag account này vào diện khả nghi chứ chưa kết luận được rằng nó có bị compromise hay chưa.

Để phân tích rõ hơn hành vi bất thường mà attacker thực hiện khi mà đã chiếm được tài khoản của ai đó mình sẽ tập trung vào thông tin sau

![Screenshot 2026-03-14 145509](https://hackmd.io/_uploads/BkPJ1iGc-g.png)

![image](https://hackmd.io/_uploads/S1wWFoG9bl.png)


EventCategory và EventName đây la thứ thể hiện rằng user đang làm gì với tài nguyên hay hệ thống AWS. [Ref]([https://](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-events.html))

`eventCategory` là để phân loại các `eventName` theo hai loại sau

| Loại Event | Ý nghĩa |
| --- | --- |
| **Management Event** | Ghi log **các hành động quản trị AWS** (tạo, sửa, xóa tài nguyên). Ví dụ -   `CreateUser`  `DeleteBucket` `StartInstances`  `AttachRolePolicy` `ListPolicies`|
| **Data Event** | Ghi log **các thao tác truy cập trực tiếp vào dữ liệu** trong tài nguyên. Ví dụ --  `ListObjects`  `GetObject` (S3 download file)  `PutObject` (upload file) `InvokeFunction` (Lambda run) |

Dưới đây là hai mẫu cho 2 loại event

![image](https://hackmd.io/_uploads/rymbv9f5Zx.png)

![image](https://hackmd.io/_uploads/HyVXP5fc-g.png)


Việc một tài khoản IAMUser có thể gọi được các thao tác quản trị tài nguyên và truy cập dữ liệu phụ thuộc vào account đó có được cấp policy để truy cập hay không, cho nên ta có thể đánh giá sự đáng nghi nếu một tài khoản được cấp quá nhiều quyền, không bị giới hạn bởi policy. 



Và để xem chi tiết rằng trong các IAMUser account trên kia đã thực hiện các hành động gì mình dùng query sau để xem chi tiết

```!
sourcetype="aws:cloudtrail" userIdentity.type=IAMUser
| stats values(eventName) as eventNames dc(eventName) as eventTypeCount by userIdentity.accountId userIdentity.userName
| sort - eventTypeCount
```

Query trên mình dùng để xem với mỗi account IAMUser họ đã thực hiện các thao tác nào đối với hệ thống và dữ liệu trên AWS

[FULL_RESULT](https://fptsoftware362-my.sharepoint.com/my?id=%2Fpersonal%2Fdathn5%5Ffpt%5Fcom%2FDocuments%2FSearch%5Fevent%5Feach%5Fuser%2Ehtml&parent=%2Fpersonal%2Fdathn5%5Ffpt%5Fcom%2FDocuments)

Kết quả mình nhận được như sau account `helpdesk.luke` có số lượng event các loại được call tới nhiều nhất 42 loại, sau đó là
- `cloudops.ryan` 40 loại
- `admin.john` 25 loại
- `dataanalyst.sarah` 24 loại
- `marketing.sophia` 20 loại
- `devops.ethan` 19 loại
- `appdev.mark` 15 loại
- `frontenddev.chris` 9
- `sysadmin.mary` 8
- `backenddev.lisa` 6
- `itmanager.david` 5
- `customersupport.adam` 3 
- `devops.kate` 2
- `Cloud.Admin` 1

![Screenshot 2026-03-16 091511](https://hackmd.io/_uploads/S1I5nJr5We.png)

![Screenshot 2026-03-16 093349](https://hackmd.io/_uploads/Bka5nJS5-x.png)

![Screenshot 2026-03-16 093401](https://hackmd.io/_uploads/S1Wo2yS9bx.png)

![Screenshot 2026-03-16 093412](https://hackmd.io/_uploads/r1ws21B9Wg.png)

![Screenshot 2026-03-16 093421](https://hackmd.io/_uploads/SknohkB5Zl.png)

![Screenshot 2026-03-16 093429](https://hackmd.io/_uploads/ryG23yrqZe.png)

![Screenshot 2026-03-16 093437](https://hackmd.io/_uploads/S1Dn3Jr9bx.png)

![Screenshot 2026-03-16 093449](https://hackmd.io/_uploads/HJ2n2yB5We.png)

![Screenshot 2026-03-16 093500](https://hackmd.io/_uploads/ryxp21Bq-x.png)


Do account `helpdesk.luke` có số lượng các loại truy cập tới hệ thống và tài nguyên của AWS khá lơn nên mình sẽ bắt đầu nghiên cứu trước để xem có điểm gì nổi bật đáng ngờ hay không.

![image](https://hackmd.io/_uploads/B1FWTJS5Zg.png)

Trước tiên mình nhận thấy account này đã thực hiện 4 loại event mà mọi account khác đều không có đó là

- **`AddUserToGroup`** - Thêm một IAM user vào một IAM group (user sẽ kế thừa các permission/policy gắn với group đó).
- **`AttachUserPolicy`** - Gắn một managed policy vào IAM user để cấp quyền theo policy đó
- **`CreateLoginProfile`** - Tạo login profile (mật khẩu) cho IAM user để user có thể đăng nhập AWS
- **`CreateUser`** - Tạo mới một IAM user trong account AWS.

Đây là một hành vi rất dang ngờ bởi việc một account thuộc loại IAMUser thường bị hạn chế quyền bởi các policy, và việc tạo IAM User mới thì cần tới root account mới có thể làm được việc này

Trace theo từng event của account `helpdesk.luke` để phân tích hành vi.

Bắt đầu với việc tạo mới 1 IAM user
```!
sourcetype="aws:cloudtrail" userIdentity.type=IAMUser  "userIdentity.accountId"=141573590337 "userIdentity.userName"="helpdesk.luke" eventName=CreateUser
```

![image](https://hackmd.io/_uploads/B1ERyxBqZe.png)

MÌnh thấy rằng 1 IAM user mới có userName là marketing.mark được tạo thành công vào lúc 9:59:33 2-11-2023

Sau đó thì thấy accoutn đó được tạo pass mới qua event `CreateLogininProfile`

![image](https://hackmd.io/_uploads/rJg5elBcZe.png)

Tiếp là gắn thêm policy `IAMUserChangePassword` đây là 1 policy thông thường cho phép IAM user tự đổi mật khẩu đăng nhập AWS Management Console của chính họ. 

![image](https://hackmd.io/_uploads/H1EiWgS5-e.png)

Tiếp là account vừa được tạo kia lại được thêm vào group Admin, đây có thể coi là một hành vi đáng ngờ khi mà một account IAMUser lại có nhiều quyền hạn trên AWS như vậy vừa có thể tạo account mới gắn policy và thêm vào group.

![image](https://hackmd.io/_uploads/ryQqGgB9bx.png)



Bên cạnh các hành vi trên còn có một hành vi nữa đặc biệt nguy hiểm mà account `helpdesk.luke` làm đó là thực hiện **`PutBucketPublicAccessBlock`**. [Document](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutPublicAccessBlock.html)

![image](https://hackmd.io/_uploads/rk6K5eHcWg.png)

Đây là một việc nguy hiểm PutBucketPublicAccessBlock cho phép cấu hình các cài đặt của bucket S3 để chặn hoặc hạn chế truy cập công khai, thực thi sự kết hợp hạn chế nhất của các chính sách ở cấp bucket và cấp tài khoản.

Nó có các cờ (flag) điều khiển như sau:
- BlockPublicAcls: chặn public ACL
- IgnorePublicAcls: bỏ qua public ACL đang tồn tại
- BlockPublicPolicy: chặn bucket policy public
- RestrictPublicBuckets: hạn chế/khóa public access ngay cả khi policy/ACL public

Trong request được gửi đi 4 flag đều là `false` có nghĩa là lớp Block Public Access sẽ hoàn toàn biến mất đối với bucket `backup-and-restore98825501`, điều này khiến cho các account khác nếu như có đủ quyền có thể truy cập được bucket đó. Cộng thêm việc ngay sau đó account này có tạo 1 account mới và thêm thẳng vào group `Admin` càng chứng tỏ việc này hoàn toàn là có chủ đích độc hại.

```!
sourcetype="aws:cloudtrail" userIdentity.type=IAMUser userIdentity.userName=helpdesk.luke
| stats values(eventName) as eventNames by userIdentity.accountId userIdentity.userName _time
| sort - _time
```
```!
sourcetype="aws:cloudtrail" userIdentity.type=IAMUser userIdentity.userName=helpdesk.luke
| table _time userIdentity.accountId userIdentity.userName eventName sourceIPAddress
| sort -_time

```

Dựa và query trên tóm tắt lại hành vi của account `helpdesk.luke` như sau:
- Fail login nhiều lần trong thời gian ngắn

![image](https://hackmd.io/_uploads/SkprkZH9Wg.png)
    
- Sau đó thực hiện liên tiếp nhiều hành vi để reconnaissance trong thời gian cực ngắn có thể việc này là dùng tool

![image](https://hackmd.io/_uploads/Byrak-rqbg.png)

- Sau đó là thực hiện việc **PutBucketPublicAccessBlock**

![image](https://hackmd.io/_uploads/ry0ZeWH9bg.png)

- Tiếp đó sau khi thấy việc chỉ put bucket backup kia ra public mà không truy cập được ngay hắn đã tìm kiếm các policy đang có và các cấu hình liên quan tới cấu trúc của tổ chức, các access key

![image](https://hackmd.io/_uploads/rJ_Cx-B5bg.png)

![image](https://hackmd.io/_uploads/H1F5GQS9-l.png)


- Sau cùng là tạo thêm một account mới và thêm account đó vào group Admin có thể là để cho việc duy trì truy cập hệ thống sau này - persistance

![image](https://hackmd.io/_uploads/Hy_t-WS5be.png)

![image](https://hackmd.io/_uploads/HJF7mQrqZl.png)

Sau đó attacker kiểm tra các thông tin như account mới tạo đã có trong hệ thông chưa và lấy cert key truy cập của account mới tạo, nếu có cert này có thể login vào được account và truy cập tài nguyên trên AWS.

![image](https://hackmd.io/_uploads/SyX1rmrqZl.png)

![image](https://hackmd.io/_uploads/BkdyDXB9We.png)


Từ các thông tin trên mình kết luận rằng account bị compromise là `helpdesk.luke`

>Flag: `helpdesk.luke`

--- 
#### Q2 We must investigate the events following the initial compromise to understand the attacker's motives. What is the timestamp for the first access to an S3 object by the attacker?

Các activity đối với một S3 Object có thể có những loại sau: 

| Activity Type | Example API Calls | Description |
| -------- | -------- | -------- |	
| Read |	GetObject, HeadObject |	Download or check metadata of an object. |
| Write/Upload |	PutObject, CompleteMultipartUpload	 | Upload or update an object. |
|Delete	|DeleteObject, DeleteObjects	|Remove one or more objects.|
|List	|ListObjectsV2	|Retrieve a list of objects in a bucket.|
|Copy/Move	|CopyObject|	Duplicate an object within or across buckets.|
|Restore	|RestoreObject	|Restore an archived object from Glacier.|
|Tagging	|PutObjectTagging, DeleteObjectTagging	| Add or remove tags from an object.|

Khi login attacker dùng IP `185.192.70.84` nhưng sau đó đã đổi sang nhiều IP khác nhưng vẫn trong dải `185.192.70` trong đó `185.192.70.84` là dùng nhiều nhất

Hành vi liên quan tới việc truy cập có liên quan tới S3 Object đầu tiên của attacker là **`ListIndexes`** để liệt kê tất cả các indexes của AWS Resource Explorer đang hoạt động trong các vùng AWS. Lệnh này giúp xác định các khu vực đang thu thập thông tin tài nguyên, loại chỉ mục (LOCAL hoặc AGGREGATOR) và ARN của chúng.

Tiếp ngay sau đó là **`ListBuckets`** vào lúc `2023-11-02 09:55:09`

![image](https://hackmd.io/_uploads/rJM05XH5Zg.png)

ListBuckets có chức năng là trả về danh sách tất cả các bucket thuộc sở hữu của người gửi yêu cầu đã được xác thực.

![image](https://hackmd.io/_uploads/S1JxlES9Zl.png)

Sau đó là một loạt các hành vi gọi các API để thăm dò cấu hình, trạng thái, policy liên quan

![image](https://hackmd.io/_uploads/rkMPHVScbl.png)

Rồi tiếp theo đó có 1 request qua API **`ListObjects`** được dùng để liệt kê, tìm kiếm và truy xuất danh sách các đối tượng (file/dữ liệu) có trong một S3 Bucket. Nó cho phép lọc theo tiền tố (prefix), phân trang kết quả và quản lý tệp tin hiệu quả mà không cần tải dữ liệu xuống.

![image](https://hackmd.io/_uploads/rJYv2ES9Zx.png)


Ngay sau đó có một event với request với API **`GetObject`** vào lúc `2023-11-02 09:55:53`

![image](https://hackmd.io/_uploads/B1rI2NrcWe.png)


Trong AWS,  **`GetObject`** là một API call được sử dụng trong dịch vụ Amazon S3 để truy xuất nội dung của một đối tượng (object) được lưu trữ trong một bucket cụ thể. Đây thường là hành động cho việc tải xuống data có trong S3 object đó

![image](https://hackmd.io/_uploads/BkaiGSScWg.png)

Đây là thông tin của event có eventName là **`GetObject`** ta có thể thấy các thông tin như là:
-**`Host`**: research-project-files23411723.s3.us-east-1.amazonaws.com là endpoint mà attacker request tới
- **`key`**: `prototype.obj `đây là file mà attacker muốn tải xuống
- **`response-content-disposition: (attachment)`:**  Tham số này ép buộc trình duyệt của người dùng phải  **tải file xuống**  thay vì hiển thị trực tiếp trên trình duyệt. 
- **`bucketName`**:  research-project-files23411723 tên của S3 bucket chứa dữ liệu
-  **`X-Amz-Algorithm`  &  `X-Amz-SignedHeaders`:**  Cho thấy yêu cầu này sử dụng  **AWS Signature Version 4**  để xác thực. Đây là phương thức bảo mật tiêu chuẩn của AWS.
-  **`X-Amz-Expires`  (`300`):**  Đây là một  URL tạm thời. Con số  `300`  có nghĩa là liên kết tải file này chỉ có hiệu lực trong vòng  **300 giây (5 phút)**  kể từ thời điểm tạo.

---

Vậy mình kết luận rằng thời điểm mà attacker truy cập vào S3 Object là `2023-11-02 09:55:53`

>Flag: 2023-11-02 09:55:53

--- 
#### Q3 Among the S3 buckets accessed by the attacker, one contains a DWG file. What is the name of this bucket?

Để biết được rằng attacker đã truy cập các S3 bucket nào mình lọc các event với query sau 

```!
sourcetype="aws:cloudtrail" userIdentity.type=IAMUser userIdentity.userName=helpdesk.luke eventName=GetObject
| table _time userIdentity.accountId userIdentity.userName eventName sourceIPAddress
| sort -_time
```

![image](https://hackmd.io/_uploads/BkE6Srr9bg.png)

Kết quả mình nhận được là có 8 event tức attacker đã cố gắng truy cập vào S3 object để tải dữ liệu.

![image](https://hackmd.io/_uploads/rk2d8Srcbg.png)

Để lọc kỹ hơn mình dựa vào trường requestParameters.key để lọc ra các event có chứa file `.dwg`

```!
sourcetype="aws:cloudtrail" userIdentity.type=IAMUser userIdentity.userName=helpdesk.luke eventName=GetObject requestParameters.key=*dwg
| table _time userIdentity.accountId userIdentity.userName eventName sourceIPAddress requestParameters.key
| sort -_time
```

![image](https://hackmd.io/_uploads/rJhhUBB9be.png)

![image](https://hackmd.io/_uploads/ByofvSSq-g.png)

![image](https://hackmd.io/_uploads/ryDBDHBcZg.png)


kết quả là thu gọn lại được 1 event duy nhất với thông tin file dwg là `Product2_CAD_Designs.dwg` của bucket `product-designs-repository31183937`

>Flag: product-designs-repository31183937

--- 
#### Q4 We've identified changes to a bucket's configuration that allowed public access, a significant security concern. What is the name of this particular S3 bucket?

Như đã phân tích ở câu 1 attacker đã gọi tới API `PutBucketPublicAccessBlock`

![image](https://hackmd.io/_uploads/SJuGsBHqbg.png)

![image](https://hackmd.io/_uploads/SyxHsBrcZg.png)

Inspect vào event đó ta có thấy được các thông tin như:
-**`bucketName`**: backup-and-restore98825501 - là tên của bucket được chỉnh sửa cấu hình
- PublicAccessBlockConfiguration: {        
    - BlockPublicAcls:  false 
    - BlockPublicPolicy:  false 
    - IgnorePublicAcls:  false 
    - RestrictPublicBuckets:  false

Với việc các config đều bị chỉnh về false như trên thì bucket `backup-and-restore98825501` sẽ chịu ảnh hưởng như sau:
- Bucket bị gỡ bỏ lớp chặn truy cập công khai ở mức độ bucket, tuy nhiên thì chưa gỡ tới nỗi mà public user có thể access.
- Dựa vào cấu hình của ACL và Policy thì nguy cơ sẽ khác nhau nếu như ai đó cấu hình ACL, Policy lỏng lẻo thì việc bucket kia bị public trên internet là hoàn toàn có khả năng.

==> Cơ bản thì attacker vừa mở khóa cửa bảo vệ bên ngoài. Nếu các thiết lập bên trong (Policy/ACL) của đang lỏng lẻo, bất kỳ ai cũng có thể đọc hoặc tải dữ liệu trong bucket đó.

>Flag: backup-and-restore98825501

--- 
#### Q5 Creating a new user account is a common tactic attackers use to establish persistence in a compromised environment. What is the username of the account created by the attacker?

Như đã phân tích ở câu 1 ta có thấy hành vi tạo thêm một account mới để thiết lập duy trì trong môi trường xâm phạm được. Đó chính là event có eventName là `CreateUser`

![image](https://hackmd.io/_uploads/rkZ5e8H5We.png)

![image](https://hackmd.io/_uploads/H1LWbLH9We.png)

```!
requestParameters: { [-]
    userName: marketing.mark
    }
responseElements: { [-]
    user: { [-]
        arn: arn:aws:iam::141573590337:user/marketing.mark
        createDate: Nov 2, 2023 9:59:33 AM
        path: /
        userId: AIDASB5TRRVAUL5IB4BC4
        userName: marketing.mark
    }
    }
```

Inspect vào event đó ta có thể thấy những thông tin quan trọng là request tạo account gửi đi đã được chấp nhận và account đã tạo thành công đó là `marketing.mark` 

>Flag: marketing.mark

--- 
#### Q6 Following account creation, the attacker added the account to a specific group. What is the name of the group to which the account was added?


Ngay sau khi tạo xong account `marketing.mark` attacker đã thêm acc đó vào group với request `AddUserToGroup`

![image](https://hackmd.io/_uploads/SyME7IScbl.png)

Inspect vào event đó

![image](https://hackmd.io/_uploads/H1AuQLBqZe.png)

Mình thấy rằng attacker đang cố thêm account đó vào group tên là `Admins` nhưng ở mục response thì lại là `null` nên mình hiện tại chưa khẳng định chính thức rằng request này có thành công hay không do dựa vào sample của 1 request thành công thì nó như sau

![image](https://hackmd.io/_uploads/BJl8VLSqZg.png)

Nhưng ta có thể kết luận được group mà attacker cố thêm account mới tạo vào là `Admins` do chỉ có 1 event liên quan tới việc thêm user vào group của attacker

![image](https://hackmd.io/_uploads/ryVWH8Scbx.png)

>Flag: Admins

