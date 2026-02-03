---
layout: post
title: SIEM Home Lab 2 - Logging & Monitoring with Splunk Enterprise + OpenVAS
subtitle: Lab report on setting up a mini SIEM with Splunk Enterprise to collect logs from Apache web server and Windows endpoints, integrated with OpenVAS for vulnerability management.
tags: [siem, splunk, logging, monitoring, openvas, home-lab]
comments: true
mathjax: true
author: Hoàng Nguyên Đạt
---




# LAB REPORT – SIEM LOGGING & MONITORING VỚI SPLUNK ENTERPRISE + OPENVAS

**Người thực hiện:** Hoàng Nguyên Đạt  
**Môi trường lab:** 3 máy ảo (Windows Server 2019, Ubuntu 22.04, Windows 10)

---

# I. Executive Summary

Báo cáo này mô tả quá trình xây dựng một mô hình SIEM thu gọn sử dụng Splunk Enterprise làm nền tảng thu thập, lưu trữ và phân tích log từ:

* Web Server chạy Apache trên Ubuntu 22.04.
* Endpoint Windows 10 (Windows Event Logs).

Splunk Universal Forwarder (UF) được triển khai trên cả Ubuntu và Windows 10 để forward log về Splunk Enterprise chạy trên Windows Server 2019. Bên cạnh đó, OpenVAS được tích hợp trong phạm vi mô phỏng (mức cơ bản) cho bài toán vulnerability management.

Thông qua lab này, các mục tiêu chính đạt được gồm:

* Thiết lập pipeline log end-to-end (source → forwarder → indexer → SPL search).
* Chuẩn hóa index và sourcetype cho Apache và Windows Event Logs.
* Xác minh khả năng truy vấn, phân tích log bằng SPL.
* Chuẩn bị nền tảng cho các chức năng nâng cao: detection rule, alert, threat hunting và tích hợp sâu hơn với OpenVAS trong tương lai.


---

# II. Giới thiệu & Mục tiêu

## 2.1. Mục đích xây dựng lab

Lab được xây dựng với các mục tiêu:

* Thiết lập hệ thống SIEM nhỏ gọn sử dụng Splunk Enterprise.
* Thu thập log từ Web Server (Apache trên Ubuntu) và Endpoint Windows (Windows Event Logs).
* Quan sát, phân tích và chuẩn hóa dữ liệu log.
* Kiểm tra end-to-end log pipeline, đảm bảo log đi đúng luồng và không bị mất mát.
* Chuẩn bị nền tảng cho các chức năng nâng cao:
  * Viết detection rule.
  * Thiết lập alert.
  * Thực hiện threat hunting.
* Tích hợp OpenVAS ở mức cơ bản nhằm mô phỏng hoạt động vulnerability management.

## 2.2. Phạm vi (In-scope)

Trong lab này, phạm vi triển khai tập trung vào:

* Cài đặt Splunk Enterprise trên Windows Server 2019.
* Cài Splunk Universal Forwarder trên:
  * Ubuntu 22.04 (Apache Web Server).
  * Windows 10 (Endpoint).
* Thu thập và phân tích:
  * Apache access/error logs (Ubuntu 22.04).
  * Windows Event Logs (Security, System, Application).
* Xác minh log pipeline và tính toàn vẹn dữ liệu.
* Viết một số truy vấn SPL cơ bản để kiểm tra log ingestion.

## 2.3. Out-of-scope

Các nội dung sau chưa được triển khai trong phạm vi lab này:

* Thiết kế và triển khai dashboard nâng cao trong Splunk.
* Tối ưu hiệu năng Splunk (indexing, storage, search head scaling…).
* Xây dựng hệ thống alerting & correlation rule phức tạp.
* Phân tích chi tiết lỗ hổng từ kết quả scan của OpenVAS (mới dừng ở mức mô phỏng tích hợp).

---

# III. Kiến trúc hệ thống

## 3.1. Sơ đồ tổng quan (Architecture Overview)

Luồng dữ liệu tổng quát:

```text
[Windows 10 - UF] ────────────────→
                                     \
                                      → [Windows Server 2019 - Splunk Enterprise]
                                     /
[Ubuntu 22.04 - Apache + UF] ──────→
````

* Splunk Enterprise đóng vai trò indexer/search head.
* Hai Splunk Universal Forwarder (Ubuntu và Windows 10) gửi log về Splunk Enterprise qua port TCP 9997.


## 3.2. Thành phần hệ thống

### Windows Server 2019 (192.168.1.10)

* Cài đặt:

  * Splunk Enterprise.
* Vai trò:

  * Nhận log từ tất cả Splunk Universal Forwarder.
  * Lưu trữ log, thực hiện indexing.
  * Cung cấp giao diện truy vấn log bằng SPL.

### Ubuntu 22.04 (192.168.1.11)

* Cài đặt:

  * Apache Web Server.
  * Splunk Universal Forwarder.
* Nguồn log chính:

  * `/var/log/apache2/access.log`
  * `/var/log/apache2/error.log`

### Windows 10 (192.168.1.13)

* Cài đặt:

  * Splunk Universal Forwarder.
* Nguồn log chính:

  * Windows Security Event Logs.
  * System Logs.
  * Application Logs.

## 3.3. Data Flow (Luồng dữ liệu log)

1. Hệ điều hành và ứng dụng (Apache/Windows) sinh log tại máy nguồn.
2. Splunk Universal Forwarder đọc log tại local và gửi về Splunk Enterprise qua port **9997**.
3. Splunk Enterprise index log, lưu trữ vào các index tương ứng (ví dụ: `webserver`, `winsecevtx`).
4. Người dùng sử dụng Splunk Web (SPL) để truy vấn, tìm kiếm, phân tích log.

> ![Screenshot 2025-12-01 203750](https://hackmd.io/_uploads/SJAZnGj-Zg.png)


---

# IV. Danh sách máy ảo & thông số kỹ thuật

| Máy ảo | Hệ điều hành        | IP               | Vai trò                  | Ghi chú              |
| ------ | ------------------- | ---------------- | ------------------------ | -------------------- |
| VM1    | Windows Server 2019 | **192.168.1.10** | Splunk Enterprise Server | Nhận toàn bộ log     |
| VM2    | Ubuntu Server 22.04 | **192.168.1.11** | Apache + Splunk UF       | Web + log forwarding |
| VM3    | Windows 10          | **192.168.1.13** | Splunk UF                | Windows Event Logs   |

> 

---

# V. Chuẩn bị môi trường

## 5.1. Network Plan

* Subnet: `192.168.1.0/24`
* Gateway: `192.168.1.1`
* Tất cả máy ảo nằm trong cùng subnet để thuận tiện cho việc giao tiếp và forward log.

## 5.2. Các port cần thiết

| Service                       | Port | Host           |
| ----------------------------- | ---- | -------------- |
| Splunk Web UI                 | 8000 | Windows Server |
| Splunk Receiver (UF → Splunk) | 9997 | Windows Server |
| Apache Web Server             | 80   | Ubuntu         |
| SSH (quản trị Ubuntu)         | 22   | Ubuntu         |

> `netstat`
> ![image](https://hackmd.io/_uploads/H118pfoZZx.png) 
>  


## 5.3. Các tài khoản sử dụng

| Hệ thống          | Tài khoản            | Mô tả                        |
| ----------------- | -------------------- | ---------------------------- |
| Splunk Enterprise | `admin` / (mật khẩu) | Đăng nhập Splunk Web UI      |
| Ubuntu            | `user` / `root`      | SSH + quản lý Apache         |
| Windows 10        | `Administrator`      | Cài đặt & cấu hình Splunk UF |

---

# VI. Cài đặt Splunk Enterprise trên Windows Server 2019

## 6.1. Tải Splunk Enterprise

* Truy cập trang chủ Splunk.
* Tải bản **Splunk Enterprise cho Windows 64-bit** (phiên bản mới nhất tại thời điểm thực hiện lab).

> [Link download Splunk Enterprise, bản Trial Windows](https://www.splunk.com/en_us/products/splunk-enterprise.html)

## 6.2. Cài đặt

1. Chạy file cài đặt `.msi` với quyền Administrator.
2. Chọn kiểu chạy:

   * `Run Splunk as Local System User` (hoặc tài khoản dịch vụ riêng nếu có yêu cầu).
3. Thiết lập mật khẩu cho user `admin` (mật khẩu được sử dụng để đăng nhập Splunk Web UI).
4. Hoàn tất quá trình cài đặt theo wizard.

> ![Screenshot 2025-11-29 210021](https://hackmd.io/_uploads/rk8Lymo-be.png)


## 6.3. Cấu hình Splunk Receiver

Sau khi cài đặt, truy cập Splunk Web UI:

* URL: `http://192.168.1.10:8000`
* Đăng nhập bằng tài khoản `admin`.

Cấu hình port nhận log từ Universal Forwarder:

1. Vào **Settings → Forwarding and receiving → Receive data**.
2. Chọn **Configure receiving → Add New**.
3. Nhập port: `9997` → Save.

> ![image](https://hackmd.io/_uploads/r1LoJQsWZg.png)


## 6.4. Kiểm tra trạng thái Splunk

Mở Task manager kiểm tra `splunkd.exe` có đang chạy hay không:

![image](https://hackmd.io/_uploads/B11dg7iWZx.png)


## 6.5. Giao diện Splunk Web

* URL truy cập: `http://192.168.1.10:8000`
* Đăng nhập bằng tài khoản `admin`.
* Kiểm tra:

  * Trang Home hiển thị bình thường.
  * Không có thông báo lỗi license blocking (chỉ cảnh báo trial nếu có).

> ![image](https://hackmd.io/_uploads/rkS2xQsWZl.png)


---

# VII. Cài đặt Splunk Universal Forwarder trên Ubuntu 22.04

## 7.1. Giới thiệu

Trên máy Ubuntu 22.04 (IP **192.168.1.11**), Splunk Universal Forwarder (UF) được triển khai với các mục tiêu:

* Thu thập log Apache Web Server.
* Chuẩn hóa sourcetype, index và luồng dữ liệu log.
* Forward log về Splunk Enterprise (IP **192.168.1.10**, port **9997**).
* Đảm bảo việc phân quyền truy cập log tuân thủ best practice của Linux.

---

## 7.2. Tải và cài đặt Splunk UF

Chạy các lệnh sau trên Ubuntu:

```bash
wget wget -O splunkforwarder-10.0.2-6293d562290e-linux-ppc64le.tgz "https://download.splunk.com/products/universalforwarder/releases/10.0.2/linux/splunkforwarder-10.0.2-6293d562290e-linux-ppc64le.tgz"
```
Giải nén file trên vào folder `/opt`:
```bash
sudo tar -xzvf linux/splunkforwarder-10.0.2-6293d562290e-linux-ppc64le.tgz -C /opt
```

> ![image](https://hackmd.io/_uploads/HktRG7sb-x.png)

---

## 7.3. Phân quyền log cho Splunk UF (Linux Permission)

Apache log được lưu tại:

* `/var/log/apache2/access.log`
* `/var/log/apache2/error.log`

Các file này thuộc group **adm**. User chạy UF là `splunk` cần được cấp quyền đọc log:

```bash
sudo usermod -aG adm splunk
```

Kiểm tra lại:

```bash
groups splunk
```

Giải thích:

* Đây là best practice: cấp quyền qua group thay vì chỉnh sửa trực tiếp permission file log.
* Đảm bảo Splunk có thể đọc log mà không phá vỡ mô hình bảo mật mặc định của hệ thống.

> ![image](https://hackmd.io/_uploads/S18b7msbZg.png)


---

## 7.4. Cấu hình kết nối tới Splunk Enterprise (outputs.conf)

Chuyển sang user `splunk`:

```bash
sudo su - splunk
```

Tạo file cấu hình:

```bash
vim /opt/splunkforwarder/etc/system/local/outputs.conf
```

Nội dung:

```ini
[tcpout]
defaultGroup = indexers

[tcpout:indexers]
server = 192.168.1.10:9997
```

Giải thích:

* `192.168.1.10:9997`: địa chỉ Splunk Enterprise trên Windows Server 2019.
* `defaultGroup = indexers`: tất cả luồng log sẽ route tới nhóm này.

> ![image](https://hackmd.io/_uploads/HyXrm7iW-g.png)


---

## 7.5. Cấu hình Apache log source (inputs.conf)

Tạo file:

```bash
vim /opt/splunkforwarder/etc/system/local/inputs.conf
```

Nội dung:

```ini
[monitor:///var/log/apache2/access.log]
source = apache
sourcetype = apache_access_log
index = webserver
_TCP_ROUTING = indexers

[monitor:///var/log/apache2/error.log]
source = apache
sourcetype = apache_error_log
index = webserver
_TCP_ROUTING = indexers
```

Giải thích:

* `monitor:///...`: chỉ định file log cần theo dõi.
* `sourcetype = apache_access_log` / `apache_error_log`: chuẩn hóa định dạng log cho mục đích parsing.
* `index = webserver`: tập trung log web vào một index riêng biệt.
* `_TCP_ROUTING = indexers`: route log theo group đã định nghĩa trong `outputs.conf`.

>![image](https://hackmd.io/_uploads/rywHEQiZZx.png)


---

## 7.6. Khởi động lại Splunk UF

Áp dụng cấu hình mới:

```bash
sudo /opt/splunkforwarder/bin/splunk restart
```

Kiểm tra trạng thái:

```bash
sudo /opt/splunkforwarder/bin/splunk status
```

Kỳ vọng: `splunkd is running`.

> ![image](https://hackmd.io/_uploads/BkzY4XsZWe.png)


---

## 7.7. Xác minh Forwarder đã kết nối tới Splunk Enterprise

Trên Splunk Enterprise:

**Cách 1 – Forwarder Management**

* Vào **Settings → Forwarder Management → Forwarders**.
* Kiểm tra host Ubuntu (192.168.1.11) đã xuất hiện, trạng thái **Active**.

**Cách 2 – Dùng SPL kiểm tra log Apache**

```spl
index=webserver sourcetype=apache_access_log
| head 20
```

Hoặc:

```spl
index=webserver host=ubuntu* OR host=192.168.1.11
| stats count by sourcetype
```

Nếu có log trả về, chứng tỏ UF đã forward log thành công.

>![image](https://hackmd.io/_uploads/HyKpE7jZbe.png)


---

## 7.8. Kiểm tra pipeline log và field extraction

Dùng SPL để kiểm tra các trường quan trọng:

```spl
index=webserver sourcetype=apache_access_log
| table _time, host, clientip, method, uri, status, useragent
| head 20
```

Kỳ vọng:

* Các trường `clientip`, `method`, `uri`, `status`, `useragent` được extract chính xác.
* Thời gian `_time` trùng khớp với thời điểm request thực tế.

> ![image](https://hackmd.io/_uploads/H1AUKQsZZe.png)


---

# VIII. Cài đặt Splunk Universal Forwarder trên Windows 10 (192.168.1.13)

## 8.1. Mục tiêu

Trên Windows 10, Splunk UF được sử dụng để thu thập:

* Security Event Logs.
* System Logs.
* Application Logs.

Các log này được gửi về index `main` trên Splunk Enterprise, phục vụ:

* Giám sát đăng nhập, thay đổi chính sách.
* Phân tích lỗi hệ thống, ứng dụng.
* Kết hợp với log Apache để hỗ trợ điều tra sự cố toàn diện.

---

## 8.2. Cài đặt Splunk UF trên Windows

Các bước chính:

1. Tải Splunk Universal Forwarder for Windows (64-bit) từ trang Splunk.
2. Chạy file `.msi` với quyền Administrator.
3. Trong wizard cài đặt:


> Chọn accept và mục on-premises
>![image](https://hackmd.io/_uploads/Sy3stmjZ-e.png)
> Tạo credential
>![image](https://hackmd.io/_uploads/BJ3hYXiW-l.png)
> Bỏ qua bước này
> ![image](https://hackmd.io/_uploads/rycmqXoWbx.png)
> Điền `ip` của máy chạy splunk enterprise indexer server
> ![image](https://hackmd.io/_uploads/SykFcQjZZg.png)



 

---

## 8.3. Enable Windows Event Logs

### Cấu hình qua inputs.conf

Tại đường dẫn sau thêm file inputs.conf:

```text
C:\Program Files\SplunkUniversalForwarder\etc\system\local
```

Thêm nội dung:

>![Screenshot 2025-11-29 205714](https://hackmd.io/_uploads/r1IBimibbe.png)

Sau đó vào Task manager tìm chọn Splunk UF như hình chọn restart
>![image](https://hackmd.io/_uploads/SJtRjQobWl.png)




---

## 8.4. Kiểm tra kết nối và log Windows trong Splunk

Trên Splunk Enterprise:

```spl
index="winsecevtx"
| stats count by sourcetype
```

Kỳ vọng:

* Xuất hiện các sourcetype:
  `WinEventLog:Security`, `WinEventLog:System`, `WinEventLog:Application`.

Ví dụ truy vấn chi tiết Security Log:

```spl
index=winsecevtx sourcetype="WinEventLog:Security"
| table _time, host, EventCode, Account_Name, Logon_Type
| head 20
```
> ![image](https://hackmd.io/_uploads/HygWja7sWZl.png)
```spl
index=winsecevtx sourcetype="WinEventLog:Security"
| where isnotnull(Logon_Type) and EventCode=4625         
| table _time, host, EventCode, Account_Name, Logon_Type
| sort Logon_Type                       
| head 20
```

> ![image](https://hackmd.io/_uploads/B1QKRQoZbg.png)


---


# IX. Kiểm thử Log từ Ubuntu (Apache, Syslog, Auth.log)

## 9.1. Vị trí các file log quan trọng trên Ubuntu 22.04

Trên máy chủ Ubuntu 22.04, các log chính được sử dụng trong lab gồm:

1. **Apache Web Server**

   * Access log:
     ` /var/log/apache2/access.log`
   * Error log:
     `/var/log/apache2/error.log`

2. **Syslog hệ thống**

   * System log tổng hợp:
     `/var/log/syslog`

3. **Log xác thực (Authentication / SSH)**

   * Auth log:
     `/var/log/auth.log`

Các file này đã được cấu hình trong `inputs.conf` của Splunk Universal Forwarder (trình bày ở Mục VII) để gửi về Splunk Indexer với index và sourcetype tương ứng.

---

## 9.2. Sinh log test cho Apache Web Server

Từ một máy client (Windows, Kali, hoặc bất kỳ máy nào trong cùng subnet với Ubuntu), thực hiện các request HTTP đến web server:

```bash
curl http://192.168.1.11/
curl http://192.168.1.11/khongtontai
```

Trong đó:

* Lệnh thứ nhất: truy cập trang mặc định, dự kiến sinh log HTTP **200 OK**.
* Lệnh thứ hai: truy cập đường dẫn không tồn tại, dự kiến sinh log HTTP **404 Not Found**.

Có thể thay thế `curl` bằng trình duyệt (Chrome, Firefox…) truy cập trực tiếp:

* `http://192.168.1.11/`
* `http://192.168.1.11/khongtontai`

> **[Screenshot 22]**:

---

## 9.3. Sinh log test cho Auth.log (SSH / đăng nhập)

Để sinh log liên quan đến xác thực đăng nhập (SSH), thực hiện trực tiếp từ một máy khác trong cùng mạng (hoặc từ host/VM khác):

1. Thử đăng nhập SSH **sai mật khẩu** vài lần:

   ```bash
   ssh testuser@192.168.1.11
   # Nhập sai password 3–5 lần
   ```

2. Sau đó, thử đăng nhập **đúng mật khẩu** ít nhất một lần (nếu có user hợp lệ):

   ```bash
   ssh testuser@192.168.1.11
   # Nhập đúng password
   ```

Kết quả mong đợi:

* Trong `/var/log/auth.log` sẽ xuất hiện các dòng:

  * `Failed password for ...` (thử đăng nhập sai)
  * `Accepted password for ...` (đăng nhập thành công)

Các sự kiện này sẽ được Universal Forwarder thu thập và gửi về Splunk (index dùng cho auth.log, ví dụ: `ubuntusv-authlog`).

> **[Screenshot 23]**:

---

## 9.4. Sinh log test cho Syslog (Ubuntu System Log)

Để xác nhận Splunk đang thu thập đúng log hệ thống từ `/var/log/syslog`, có thể sinh một số sự kiện đơn giản:

1. Ghi log thủ công bằng lệnh `logger`:

   ```bash
   logger "TEST_SYSLOG: Đây là log test gửi từ máy ubtsv-vm"
   ```

2. Thực hiện một số hành động tạo log hệ thống, ví dụ:

   * Sử dụng `sudo` với lệnh bất kỳ:

     ```bash
     sudo ls /root
     ```

   * Restart một service:

     ```bash
     sudo systemctl restart apache2
     ```

Các hành động trên sẽ sinh thêm thông tin trong `/var/log/syslog`, đồng thời được gửi về Splunk thông qua Universal Forwarder.

> **[Screenshot  24]**: 

---

## 9.5. Kiểm tra log Apache trong Splunk

Trên Splunk Enterprise, truy vấn log access của Apache:

```spl
index=webserver sourcetype=apache_access_log
| table _time, host, clientip, method, uri, status, useragent
| head 20
```

Hoặc chỉ tập trung vào các request lỗi HTTP 404:

```spl
index=webserver sourcetype=apache_access_log status=404
| stats count by uri, clientip
```

Các điểm cần kiểm tra:

* Có log từ đúng host web server (ví dụ: `ubtsv-vm` hoặc IP `192.168.1.11`).
* Các request test:

  * `/`
  * `/khongtontai`
    đã được ghi nhận đầy đủ.
* Các trường (fields) như: `clientip`, `method`, `uri`, `status`, `useragent` đã được trích xuất chính xác.
* Thời gian `_time` trên Splunk khớp với thời điểm thực hiện lệnh `curl`/truy cập từ client.

> **[Screenshot 25]**: 
---

## 9.6. Kiểm tra log Auth.log (SSH) trong Splunk

Trên Splunk, kiểm tra log đăng nhập/SSH từ index dùng cho auth.log (ví dụ):

```spl
index=ubuntusv-authlog sourcetype=ubuntu-authlog "Failed password"
| table _time, host, user, src, message
| head 20
```

Hoặc thống kê số lần đăng nhập sai theo nguồn (IP):

```spl
index=ubuntusv-authlog sourcetype=ubuntu-authlog "Failed password"
| stats count as failed_count by src, user
| sort - failed_count
```



> **[Screenshot 26]**:

---

## 9.7. Kiểm tra log Syslog trong Splunk

Đối với log hệ thống được forward từ `/var/log/syslog`, trên Splunk:

```spl
index=ubuntusv-syslog sourcetype=ubuntu-system-log
| table _time, host, facility, severity, message
| head 20
```

Để kiểm tra log test gửi bằng `logger`:

```spl
index=ubuntusv-syslog sourcetype=ubuntu-system-log "TEST_SYSLOG"
| table _time, host, message
```



> **[Screenshot 27]**: 

---


