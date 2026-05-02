---
title: '[Level-3]-PacketDetective'
date: 2026-03-14

---

# Lab Report - PacketDetective  
**DatHN5 - SO3 - FSAS**


Analyze network traffic in PCAP files using Wireshark to extract IOCs and reconstruct attacker tactics like authentication and remote execution. 

**Category**: Network Forensics 
**Tactics**: Execution Defense Evasion Command and Control 
**Tool**: Wireshark


### Scenario

In September 2020, your SOC detected suspicious activity from a user device, flagged by unusual SMB protocol usage. Initial analysis indicates a possible compromise of a privileged account and remote access tool usage by an attacker.

Your task is to examine network traffic in the provided PCAP files to identify key indicators of compromise (IOCs) and gain insights into the attacker’s methods, persistence tactics, and goals. Construct a timeline to better understand the progression of the attack by addressing the following questions.

## Write up

### File: Traffic-1.pcapng

#### Q1 The attacker’s activity showed extensive SMB protocol usage, indicating a potential pattern of significant data transfer or file access.  What is the total number of bytes of the SMB protocol?

Để xác định lưu lượng được truyền qua giao thức `SBM` mình chọn `Statistics -> Protocol Hierarchy` để xem thông tin về lưu lượng của các giao thức đã truyền, trong đó giao thức `SMB` là `4406` bytes

![image](https://hackmd.io/_uploads/Skl_-IaY-e.png)

:::info
>Flag: 4406
:::

#### Q2 Authentication through SMB was a critical step in gaining access to the targeted system. Identifying the username used for this authentication will help determine if a privileged account was compromised.  Which username was utilized for authentication via SMB?

Để biết được attacker đã dùng tài khoản với username nào để truy cập được vào hệ thông và sử dụng giao thức SMB để truyền/gửi tin mình sẽ tìm các gói tin mà có info có liên quan tới `NTLMSSP_AUTH` đây là gói tin chứa các thông tin liên quan tới tài khoản và mật khẩu để truy câp được vào hệ thống `SMB` 

`NTLMSSP_AUTH` là bước cuối cùng trước đó còn hai bước là `NEGOTIATE` và `CHALLENGE`

![image](https://hackmd.io/_uploads/B1CpGLpKZx.png)

Thông tin từ gói `AUTH` cho mình biết username là: `Administrator`

:::info
>Flag: `Administrator`
:::


#### Q3 During the attack, the adversary accessed certain files. Identifying which files were accessed can reveal the attacker's intent.  What is the name of the file that was opened by the attacker?


![image](https://hackmd.io/_uploads/BylOS8aK-l.png)

Phân tích gói tin mình thấy rằng attacker đã connect tới network share với path: `\\172.16.66.36\IPC$` và tìm tới file `eventlog`, attacker đã thực hiện request để mở quyền đọc và ghi file `eventlog`

:::info
>Flag: eventlog
:::


#### Q4 Clearing event logs is a common tactic to hide malicious actions and evade detection. Pinpointing the timestamp of this action is essential for building a timeline of the attacker’s behavior.  What is the timestamp of the attempt to clear the event log? (24-hour UTC format)

YYYY-MM-DD HH:MM

Qua phân tích gói tin mình biết được attacker đã xoá hẳn file `eventlog` đi để che dấu hành vi. Sau khi xoá file log attacker đã thoát ra và đăng nhập lại để check file log đã xoá hoàn toàn hay chưa, error `NT Status: STATUS_OBJECT_NAME_NOT_FOUND (0xc0000034)` cho thấy rằng attacker đã xoá thành công. 

![image](https://hackmd.io/_uploads/rJsyvUTYWx.png)

Attacker đã thực hiện request `ClearEventLogW` để xoá file vào lúc Sep 23, 2020 16:50:16.731550000 UTC

![image](https://hackmd.io/_uploads/r1FvPUTYbg.png)

![image](https://hackmd.io/_uploads/r1wXuIpYbe.png)

:::info
>Flag: 2020-09-23 15:50
:::



### File: Traffic-2.pcapng


#### Q5 The attacker used "named pipes" for communication, suggesting they may have utilized Remote Procedure Calls (RPC) for lateral movement across the network. RPC allows one program to request services from another remotely, which could grant the attacker unauthorized access or control.  What is the name of the service that communicated using this named pipe?

\*\*\*\*\*
Qua tìm hiểu thì thông tin về `named pipe` mình biết được đây là một cơ chế trong Windows thuộc cơ chế IPC () cho phép các tiến trình trao đổi thông tin với nhau trong cùng một máy hoặc là các máy trong mạng.

- Named pipe là một đối tượng (object) có tên trong hệ điều hành (thường dưới dạng \\.\pipe\pipename).
- Một tiến trình tạo pipe (server), tiến trình khác kết nối (client) qua chính tên pipe.
- Dữ liệu truyền qua pipe là dạng luồng byte hoặc thông điệp, thứ tự tuần tự.
- Named pipe hỗ trợ cơ chế đồng bộ, xác thực, và bảo mật dựa trên quyền truy cập của Windows.


Tìm hiểu rõ hơn mình biết rằng những dấu hiệu sau cho thấy máy tính đang kết nối tới `named pipe`:

- Tên pipe xuất hiện trong request/kết nối SMB/DCE-RPC.
- Gói mở hoặc bind kết nối tới pipe (dựa vào tên pipe trong trường thông tin).
- Bật đầu của chuỗi giao dịch (transaction chain) liên quan đến pipe ở tầng ứng dụng hoặc dịch vụ tương ứng.

Do đó mình đã tìm tới các gói tin với giao thức là `DCE/RPC` để kiểm tra thông tin chi tiết. 

Sau khi xem qua các gói tin minh thấy các gói này có rất nhiều lớp thông tin nên mình quyết định search với keywork `PIPE` để xem cho nhanh, nhấn `Ctrl + F` rồi search mình nhận được kết quả là có hai named pipe đang được kết nối tới đó là `\\PIPE\atsvc` và `\\PIPE\SessEnvPublicRpc`. Và kết quả đúng cho câu hỏi này là `atsvc`

![image](https://hackmd.io/_uploads/SkWBgPTYbl.png)

:::info
>Flag: `atsvc`
:::



#### Q6 Measuring the duration of suspicious communication can reveal how long the attacker maintained unauthorized access, providing insights into the scope and persistence of the attack. What was the duration of communication between the identified addresses 172.16.66.1 and 172.16.66.36?


Để biết thời lượng mà IP 172.16.66.1 and 172.16.66.36 giao tiếp với nhau mình sẽ vào mục `Statistics -> Conversations` trên wireshark để làm rõ.

![image](https://hackmd.io/_uploads/BJyPQvpKWg.png)

Mình sẽ dựa vào kết nối qua IPv4 để xác định tổng thời lượng mà hai máy giao tiếp với nhau, trong cửa sổ Conversation mình thấy hai máy kết nối trong vòng 11.7247s cũng chính là tổng thời mà file PCAP này capture được.

![image](https://hackmd.io/_uploads/S1TPNw6tZg.png)


\*\*.\*\*\*\*
:::info
>Flag: 11.7247
:::

###  File: Traffic-3.pcapng


#### Q7 The attacker used a non-standard username to set up requests, indicating an attempt to maintain covert access. Identifying this username is essential for understanding how persistence was established. Which username was used to set up these potentially suspicious requests?

Mở file PCAP ra mình thấy có các gói SMB nên mình tập trung luôn vào gói tin có chứa thông tin `NTLMSSP_AUTH` để trích xuất các thông tin liên quan tới tài khoản, qua đó mình tìm được username mà attacker dùng để truy cập vào hệ thông SMB là `backdoor`

![image](https://hackmd.io/_uploads/BJBfDDptWl.png)

:::info
>Flag: backdoor
:::


#### Q8 The attacker leveraged a specific executable file to execute processes remotely on the compromised system. Recognizing this file name can assist in pinpointing the tools used in the attack. What is the name of the executable file utilized to execute processes remotely?

\*\*\*\*\*\*\*\*.\*\*\*
Qua quan sát các gói tin mình thấy attacker kết nối vào network share ADMIN$, rồi thực hiện request tới file `PSEXESVC.exe` 

![image](https://hackmd.io/_uploads/Bkmldv6F-e.png)

![image](https://hackmd.io/_uploads/H1pvuwTF-x.png)

![image](https://hackmd.io/_uploads/SJh_ODTF-l.png)

![image](https://hackmd.io/_uploads/HyBouwpFWg.png)

:::info
>Flag: PSEXESVC.exe
:::

