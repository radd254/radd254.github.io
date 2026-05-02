---
title: '[Level-2]- NerisBot'

---

# Lab Report - NerisBot  
**DatHN5 - SO3 - FSAS**

Reconstruct the attack timeline by correlating Suricata and Zeek logs in Splunk to identify malicious IPs, C2 domains, targeted hosts, and file hashes.

Category: Threat Hunting
Tactic: Command and Control
Tool: Splunk

### Scenario
Unusual network activity has been detected within a university environment, indicating potential malicious intent. These anomalies, observed six hours ago, suggest the presence of command and control (C2) communications and other harmful behaviors within the network.

Your team has been tasked with analyzing recent network traffic logs to investigate the scope and impact of these activities. The investigation aims to identify command and control servers and uncover malicious interactions.

## Write up

Tình huống:
- Có một hành vi bất thường liên quan tới network liên quan tới việc giao tiếp của C2 
- Attacker đã kết nối tới máy nạn nhân và tải xuống file exe ngụy trang dưới dạng txt vào máy nạn nhân

Mình dùng query sau để xem các loại source và sourcetype có trong log

```spl!
index =*
| stats count by index source sourcetype
```

![image](https://hackmd.io/_uploads/HJWNe7fs-l.png)

Có hai loại log từ hai nguồn chính đó là từ `zeek` - còn gọi là (bro) và `suricata` - loại IDS

- Độ ưu tiên: conn.log, dns.log, http.log và files.log thường là nguồn dữ liệu chính cho việc network traffic analysis và threat hunting.
- Cảnh báo: notice.log, weird.log là nơi tập trung security alerts của Zeek; nên giám sát thường xuyên.
- Ta có thể liên kết log zeek với suricata để có thể nhìn được 1 ngữ cảnh đầy đủ

| sourcetype | source (đường dẫn) | **Ý nghĩa / nội dung chính** | 
|------------|-------------------|------------------------------|
| **zeek:conn** | `/home/ubuntu/bro/conn.log` | Kết nối TCP/UDP – mỗi dòng mô tả một flow (srcIP, srcPort, destIP, destPort, protocol, duration, bytes in/out, trạng thái). |
| **zeek:dns** | `/home/ubuntu/bro/dns.log` | Truy vấn và trả lời DNS – chứa query type, queried name, response code, answer IP và TTL. | 
| **zeek:http** | `/home/ubuntu/bro/http.log` | Lưu lượng HTTP – method, uri, host, status code, content‑type, user‑agent, referrer, byte size. | 
| **zeek:files** | `/home/ubuntu/bro/files.log` | Thông tin về các file được “see” trong traffic (MD5/SHA1, MIME, size, con‐type, extracted file path). | 
| **zeek:syslog** | `/home/ubuntu/bro/syslog.log` | Sự kiện hệ thống Zeek (script load, warning, error) – dùng để debug scripts. | 96 337 |
| **zeek:ssl** | `/home/ubuntu/bro/ssl.log` | Handshake TLS/SSL – version, cipher, server name, certificate fields (subject, issuer, validity). | 
| **zeek:weird** | `/home/ubuntu/bro/weird.log` | Các hành vi bất thường không khớp với các log chuẩn (truncated packet, malformed header,…). | 
| **zeek:x509** | `/home/ubuntu/bro/x509.log` | Chi tiết certificate X.509 được trao đổi trong TLS – subject, issuer, SAN, fingerprint. | 
| **zeek:ssh** | `/home/ubuntu/bro/ssh.log` | Phiên SSH – client IP, server IP, version strings, auth method, success/failure. | 
| **zeek:dpd** | `/home/ubuntu/bro/dpd.log` | “Dynamic protocol detection” – xác định protocol dựa trên payload (ex: detecting http trên non‑standard port). |
| **zeek:snmp** | `/home/ubuntu/bro/snmp.log` | Truy vấn/response SNMP – community, OID, value, version. | 
| **zeek:mysql** | `/home/ubuntu/bro/mysql.log` | Giao thức MySQL – user, db, query, response‑size. | 2 748 |
| **zeek:sip** | `/home/ubuntu/bro/sip.log` | Lưu log SIP (VoIP) – method, call‑id, status, from/to URIs. | 
| **zeek:notice** | `/home/ubuntu/bro/notice.log` | Cảnh báo Zeek – rule ID, msg, severity, src/dest IP/port. | 
| **zeek:tunnel** | `/home/ubuntu/bro/tunnel.log` | Thông tin tunnel (ex: VPN, SSH tunnel) – inner/outer IP/port, protocol. | 
| **zeek:loaded_scripts** | `/home/ubuntu/bro/loaded_scripts.log` | Các script Zeek đã được load trong phiên – tên, path, thời gian load. | 
| **zeek:ftp** | `/home/ubuntu/bro/ftp.log` | Lưu lượng FTP – commands, responses, transfer size, user. | 
| **zeek:smtp** | `/home/ubuntu/bro/smtp.log` | Giao thức SMTP – mail‑from, rcpt‑to, subject (nếu có), status. | 
| **zeek:dhcp** | `/home/ubuntu/bro/dhcp.log` | Giao dịch DHCP – request/offer, client MAC, assigned IP, lease time. | 
| **zeek:app_stats** | `/home/ubuntu/bro/app_stats.log` | Thống kê tổng quan (số event, bytes) của các log Zeek trong một khoảng thời gian. | 
| **zeek:pe** | `/home/ubuntu/bro/pe.log` | Phân tích Portable Executable (PE) – header fields, sections, imports/exports. | 
| **zeek:rdp** | `/home/ubuntu/bro/rdp.log` | Lưu chi tiết Remote Desktop Protocol – version, cookie, client‑/server‑caps. | 
| **zeek:packet_filter** | `/home/ubuntu/bro/packet_filter.log` | Các packet bị drop do filter (ex: BPF) – nguyên nhân, cnt. | 
| **zeek:socks** | `/home/ubuntu/bro/socks.log` | Lưu log SOCKS proxy – request type, dst IP/port, auth status. | 



### Q1: During the investigation of network traffic, unusual patterns of activity were observed in Suricata logs, suggesting potential unauthorized access. One external IP address initiated access attempts and was later seen downloading a suspicious executable file. This activity strongly indicates the origin of the attack. What is the IP address from which the initial unauthorized access originated

Tập trung vào log suricata trước

Một IP external đã bị quan sát thấy tải xuống 1 file `.exe`

Trước hết mình chạy `sourcetype=suricata` để quan sát các thông tin quan trọng có trong event log của suricata

Và mình quan sát được 2 trường thông tin quan trọng đó là `event_type` và `eventtype`

`event_type` này là của mặc định suricata để phân loại các giao thức đi qua

![image](https://hackmd.io/_uploads/ByB6ImMoZe.png)

`eventtype` này có thể là custom field được extract thoe từng loại trong đó mình thấy được trường `alert` đã được custom thành `suricata_eve_ids_attack`

![image](https://hackmd.io/_uploads/r1ChIXMibl.png)

Mình sẽ tập trung vào trường thông tin này để lọc ra các event liên quan

`sourcetype=suricata  eventtype=suricata_eve_ids_attack `

![image](https://hackmd.io/_uploads/S1BJCmfj-e.png)

```spl!
sourcetype=suricata  eventtype=suricata_eve_ids_attack http.http_user_agent=Download
| dedup http.url
| table flow.src_ip flow.dest_ip http.hostname http.http_method http.http_user_agent http.url
```

![image](https://hackmd.io/_uploads/BkiRbUGi-e.png)


```spl!
index=* sourcetype=suricata  event_type=http  http.http_user_agent="Download" 
| table src_ip dest_ip http.hostname http.http_user_agent http.protocol http.url
```

![image](https://hackmd.io/_uploads/HyxoyLzjWx.png)

Qua ba query trên mình thấy rằng máy nạn nhân đã kết nối tới 3 IP và truy cập để tải xuống khoảng vài file (có thể tên file giống nhau nhưng nội dụng thì khác)

Mình dùng query sau để tìm ra thêm từ các IP kia có hành vi gì nữa không

```spl!
index=* sourcetype=suricata  event_type=http  http.http_user_agent=* (dest_ip=195.88.191.59 OR 	60.190.223.75 OR  94.63.149.152)
|  stats values(src_ip) values(http.hostname) values(http.http_user_agent) values(http.protocol) values(http.http_method) values(http.url) by dest_ip
```

![image](https://hackmd.io/_uploads/BkEnFIMsZe.png)

Để xác định cụ thể là IP nào là nguồn gốc của file exe độc hại mình nghiên cứu zeek log, do zeek log có lưu lại metadata của các file 

`zeek:files`	| `/home/ubuntu/bro/files.log` | `Thông tin về các file được “see” trong traffic (MD5/SHA1, MIME, size, con‐type, extracted file path).`

Dùng query sau để xem log về các file

`sourcetype=zeek:files`

![image](https://hackmd.io/_uploads/HJN95LziWg.png)

Trong log thuộc sourcetype zeek:files có các trường thông tin về file như mã hash MD5,SHA1 mime_type, nguồn tải - người gửi tx_hosts, đích tải xuống rx_hosts - người nhận

Mình đã biết rằng địa chỉ IP nơi attacker tải file độc hại về chỉ là một trong ba IP sau 195.88.191.59, 94.63.149.152, 60.190.223.75

```spl!
sourcetype=zeek:files tx_hosts=195.88.191.59 ``` 94.63.149.152``` 60.190.223.75```
| dedup md5 sha1 | table md5 sha1 mime_type
```

![img](https://hackmd.io/_uploads/rklqx05jWg.png)

![image](https://hackmd.io/_uploads/HyORgA5o-x.png)

IP 60.190.223.75 thấy có 1 file nhưng không phải file độc hại

![image](https://hackmd.io/_uploads/S1zvbRqobl.png)


Ip 94.63.149.152 thì không thấy có file nào đã tải xuống được log lại 

![image](https://hackmd.io/_uploads/SkD3iIzjZe.png)

Từ IP 195.88.191.59 thấy được đã có 5 file được tải về

Dựa vào kết quả của câu 4 mình đã có được hash md5 và sha1 của các file, dựa vào đó mình search hash đó trên VirusTotal để tìm file.

![image](https://hackmd.io/_uploads/SyOd4dfo-l.png)

![image](https://hackmd.io/_uploads/rkzYVOGs-l.png)

![image](https://hackmd.io/_uploads/SJ19NOfiWl.png)

![image](https://hackmd.io/_uploads/HJc5E_Ms-g.png)

![image](https://hackmd.io/_uploads/ByBoNdMsZl.png)

5 file từ IP 195.88.191.59 đều là malware

> 195.88.191.59

### Q2: Investigating the attacker’s domain helps identify the infrastructure used for the attack, assess its connections to other threats, and take measures to mitigate future attacks. What is the domain name of the attacker server?

![image](https://hackmd.io/_uploads/rk16_LMobg.png)

> nocomcom.com

### Q3: Knowing the IP address of the targeted system helps focus remediation efforts and assess the extent of the compromise. What is the IP address of the system that was targeted in this breach?

> 147.32.84.165

### Q4: Identify all the unique files downloaded to the compromised host. How many of these files could potentially be malicious?

![image](https://hackmd.io/_uploads/SkD3iIzjZe.png)

> 5

### Q5: What is the SHA256 hash of the malicious file disguised as a .txt file?

```bash!
md5	                                sha1	
7c8d12f776b17da6576c6469d8ad5a2b	5dc958a367b495b48bb548177ae7558e842acb1f
a7d0e9196d472dbaa6948fdeb33045a0	cc32bf22df045a6e787da42e3b011eac8f02ee85
564048b35da9d447f2e861d5896d908d	2a6d5ad9a782c96f9cd214fcd105056248e6df31
42d00e295e1c3715acd51a0fc54bad87	e88ba2c9a9948f238cbdb3193e067fc95281c715
8ed68a129b3634320780719abf6635cc	29b4edb6a1ebe70a8fe876a5652ed7de067269f4
```

![image](https://hackmd.io/_uploads/Sk8aQdzi-x.png)


File malware giả dạng file txt có mã hash sha256 là 
`6fbc4d506f4d4e0a64ca09fd826408d3103c1a258c370553583a07a4cb9a6530`

> 6fbc4d506f4d4e0a64ca09fd826408d3103c1a258c370553583a07a4cb9a6530
