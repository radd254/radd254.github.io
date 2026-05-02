---
title: '[Level-3]-REvil-GOLD_SOUTHFIELD'
date: 2026-03-17

---

# Lab Report - REvil - GOLD SOUTHFIELD
**DatHN5 - SO3 - FSAS**
---

Analyze Sysmon logs in Elastic SIEM to investigate REvil ransomware attack behaviors, decode recovery sabotage commands, and identify IOCs including the C2 onion domain. 

**Category**: Threat Hunting 
**Tactics**: Execution, Persistence, Privilege Escalation, Defense Evasion, Discovery 
**Tools**: Splunk, ELK, OSINT

#### Scenario
You are a Threat Hunter working for a cybersecurity consulting firm. One of your clients has been recently affected by a ransomware attack that caused the encryption of multiple of their employees' machines. The affected users have reported encountering a ransom note on their desktop and a changed desktop background. You are tasked with using Splunk SIEM containing Sysmon event logs of one of the encrypted machines to extract as much information as possible.

### Write up



---
#### Q1 To begin your investigation, can you identify the filename of the note that the ransomware left behind?

```!
| tstats count where index=* by sourcetype
| sort - count
```

![image](https://hackmd.io/_uploads/ryM8vF8cbx.png)

Đây là format log có trong splunk



:::spoiler sample log
```!json
{
  "@timestamp": "2023-09-08T03:38:16.343Z",
  "@metadata": {
    "beat": "winlogbeat",
    "type": "_doc",
    "version": "8.12.2"
  },
  "log": {
    "file": {
      "path": "C:\\evtx\\Sysmon.evtx"
    },
    "level": "information"
  },
  "host": {
    "name": "win-2fosvi0lscf",
    "ip": [
      "fe80::d015:5cd6:b82d:7865",
      "192.168.19.129"
    ],
    "mac": [
      "00-0C-29-A6-69-68"
    ],
    "hostname": "win-2fosvi0lscf",
    "architecture": "x86_64",
    "os": {
      "name": "Windows Server 2019 Standard Evaluation",
      "kernel": "10.0.17763.5202 (WinBuild.160101.0800)",
      "build": "17763.5206",
      "type": "windows",
      "platform": "windows",
      "version": "10.0",
      "family": "windows"
    },
    "id": "9b9686bd-85d0-4505-beb2-a805093c78b1"
  },
  "ecs": {
    "version": "8.0.0"
  },
  "agent": {
    "type": "winlogbeat",
    "version": "8.12.2",
    "ephemeral_id": "17d1d3f7-67be-49b4-a2e3-642a0c95fb95",
    "id": "6153e3c4-07fe-4086-ba04-d3aca3d13952",
    "name": "WIN-2FOSVI0LSCF"
  },
  "winlog": {
    "user": {
      "identifier": "S-1-5-18",
      "domain": "NT AUTHORITY",
      "name": "SYSTEM",
      "type": "User"
    },
    "computer_name": "WIN-1RKSOVFDBN0",
    "opcode": "Info",
    "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
    "channel": "Microsoft-Windows-Sysmon/Operational",
    "provider_name": "Microsoft-Windows-Sysmon",
    "event_data": {
      "RuleName": "-",
      "UtcTime": "2023-09-08 03:38:16.343",
      "ProcessGuid": "{fc535cf3-e855-64f9-ca17-000000000200}",
      "ProcessId": "2004",
      "Image": "C:\\Windows\\system32\\mmc.exe",
      "TargetFilename": "C:\\Users\\Administrator\\Desktop\\Event Viewer\\Sysmon.evtx",
      "CreationUtcTime": "2023-09-08 03:38:16.328",
      "User": "WIN-1RKSOVFDBN0\\Administrator"
    },
    "process": {
      "pid": 6596,
      "thread": {
        "id": 4688
      }
    },
    "event_id": "11",
    "record_id": 10417,
    "api": "wineventlog",
    "version": 2
  },
  "event": {
    "kind": "event",
    "provider": "Microsoft-Windows-Sysmon",
    "created": "2024-03-21T19:02:15.358Z",
    "code": "11"
  }
}
```
:::

Ở đây cần chú ý tới một số điểm như
- `winlog.event_data.User` để xem user nào thực thi hành động nào trên hệ thống
    - ![image](https://hackmd.io/_uploads/S1y-q_JiZg.png)

- `event.code ` xem rằng hành động đó là gì

    - ![image](https://hackmd.io/_uploads/H12XqdkjZx.png)
    
- winlog.event_data.Image là tiến trình thực thi 

    - ![image](https://hackmd.io/_uploads/Sy80zY1o-e.png)
    
- winlog.event_data.TargetFilename để quan sát file đích mà tiến trình tạo ra hoặc có hành vi tác động tới

    - ![image](https://hackmd.io/_uploads/ByfLXFyjbe.png)
    
- ProcessId là Process ID của tiến trình thực hiện

    - ![image](https://hackmd.io/_uploads/HkPrLODs-l.png)



Ở đây là mình đi tìm file được tạo ra nên sẽ tập trung vào event.code 11, và thường file note có thể hay thuộc loại txt plaintext 

![image](https://hackmd.io/_uploads/rJy-Pu1iWx.png)

Nên mình có query như sau để tìm ra PID của tiến trình tạo ra các file note và vị trí file note đó

```!
index=revil   event.code=11 winlog.event_data.TargetFilename=*.txt*
| table _time winlog.event_data.User event.code winlog.event_data.ProcessId winlog.event_data.Image winlog.event_data.TargetFilename
| sort -_time
```
![image](https://hackmd.io/_uploads/SJGWr_vobl.png)


Attacker để lại file **`5uizv5660t-readme.txt`** ở rất nhiều vị trí trên máy tính nạn nhân và nó do tiến trình tên `facebook asisstant.exe` với PID 5348 

>Flag: 5uizv5660t-readme.txt

---
#### Q2 After identifying the ransom note, the next step is to pinpoint the source. What's the process ID of the ransomware that's likely involved

Phân tích các event có file note `5uizv5660t-readme.txt` kia mình thấy rằng nó có điểm chung là đều có chung `ProcessId` là 5348 và `process.pid` là 6596 và đều cùng có nguồn từ image tại `C:\Users\Administrator\Downloads\facebook assistant.exe`

![image](https://hackmd.io/_uploads/rJ5Rnu1ibe.png)


- process.pid thường là metadata phụ trợ trong hệ Splunk, có thể là PID của Splunk hoặc log collector của Windows tạo ra, không phải tiến trình ransomware.

>Flag: 5348

---
#### Q3 Having determined the ransomware's process ID, the next logical step is to locate its origin. Where can we find the ransomware's executable file?

Dựa vào thông tin process ID từ câu thứ hai mình tạo query sau để xem chi tiết hơn hành vi của file có PID 5348

```!
index=revil   *.exe winlog.event_data.ProcessId=5348
| table _time event.code winlog.event_data.User winlog.event_data.ProcessId winlog.process.pid winlog.event_data.Image  winlog.event_data.TargetFilename
```

![image](https://hackmd.io/_uploads/Sk8DDY1sWl.png)

Từ kết quả của query trên ta có thể thấy được đường dẫn tới nơi của ransomware file kia là `C:\Users\Administrator\Downloads\facebook assistant.exe`

Nhưng ngoài việc lợi dụng ransomware để tạo ra các file note txt thì mình thấy nó còn thực hiện các hành vi với event code là 13, 7, 1, 5

![image](https://hackmd.io/_uploads/rkaLRY1jWl.png)

![image](https://hackmd.io/_uploads/Bk3vRKJjWx.png)

![image](https://hackmd.io/_uploads/BJyFRKkiWx.png)

![image](https://hackmd.io/_uploads/BJSuRKJobx.png)

[Event-code-ref](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

1 - id: 13 - chỉnh sửa Registry key của `bam` - cơ chế lưu lịch sử tiến trình chạy nền để che giấu việc chạy powershell - cho phép powershell chạy dưới nền một cách chính thống khi người dùng chạy `facebook assistant.exe`

![image](https://hackmd.io/_uploads/BJVCdYyjZx.png)

2 - id: 7 - Ở đây do việc chạy ứng dụng `facebook assistant.exe` tại folder Downloads cùng với việc không có chữ ký số CA - trường sign bị đánh false nên đã bị sysmon gắn cờ nguy hiểm với technique T1574.002-DLL Side-Loading

Bên cạnh đó với hash rõ ràng như vậy mình có kiểm tra trên virustotal thì nhận được kết quả file `facebook assistant.exe` chính là Ransomware

![image](https://hackmd.io/_uploads/ByX11n1o-e.png)

[VirusTotal](https://www.virustotal.com/gui/file/b8d7fb4488c0556385498271ab9fffdf0eb38bb2a330265d9852e3a6288092aa/detection)

![image](https://hackmd.io/_uploads/Bkcwghkjbl.png)

3 - id: 1 - Cái này nói về việc Ransomware được thực thi ngay trong explorer.exe với    IntegrityLevel: High nghĩa là user thực hiện đang nắm quyền cao cụ thể trong trường hợp này chính là Administrator

![image](https://hackmd.io/_uploads/SyPUXn1jWx.png)


4 - id: 1 - là hành vi xóa log để tránh bỏ lại dấu vết của ransomware, ransomware đã tự động chạy `C:\Windows\system32\cmd.exe /c ""C:\Program Files\Graphviz\Clear_Event_Viewer_Logs.bat" "` để xóa file log và sysmon đã bắt được hành vi này và mapping sang MITRE với technique T1070.001 - Clear Windows Event Logs

![image](https://hackmd.io/_uploads/SyXfuFysZe.png)

5 - id: 5 - event id 5 là ransomware tự động xóa tiến trình của nó đi

![image](https://hackmd.io/_uploads/BJxEnKks-e.png)


>flag: C:\Users\Administrator\Downloads\facebook assistant.exe

---
#### Q4 Now that you've pinpointed the ransomware's executable location, let's dig deeper. It's a common tactic for ransomware to disrupt system recovery methods. Can you identify the command that was used for this purpose?


Như phân tích ở câu trên thì chỉ là 1 phẩn hoạt động của ransomware, tới đây ta phân tích rõ hơn việc ransonware đã thực thi hành vi / command nào khiến cho việc khôi phục được hệ thống bị gián đoạn, và như ta biết là trước đó ransomware này thì nó đã thực hiện hành vi chỉ sửa thông tin hệ thống làm cho powershell chạy ẩn dưới nền do đó việc thực thi hành vi này chắc chắn cũng chạy qua powershell để khỏi bị chặn bởi các phần mềm bảo vệ khác như WD.

Tìm ra command được thực thi qua powershell.exe mình dùng query sau

```!
index=revil  winlog.event_data.Image="*powershell.exe"
| table _time event.code winlog.event_data.User winlog.event_data.ProcessId winlog.event_data.CommandLine winlog.event_data.ParentCommandLine winlog.event_data.Image  winlog.event_data.TargetFilename
```

![image](https://hackmd.io/_uploads/ryqRi31s-e.png)

Kết quả cho ra chỉ có 1 lệnh đó là 
```!
powershell -e RwBlAHQALQBXAG0AaQBPAGIAagBlAGMAdAAgAFcAaQBuADMAMgBfAFMAaABhAGQAbwB3AGMAbwBwAHkAIAB8ACAARgBvAHIARQBhAGMAaAAtAE8AYgBqAGUAYwB0ACAAewAkAF8ALgBEAGUAbABlAHQAZQAoACkAOwB9AA==
```
![image](https://hackmd.io/_uploads/S14wTnko-x.png)

decode base64 ta được lệnh hoàn chỉnh sau 
`Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_. Delete();}`


>Flag: Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_. Delete();}

---
#### Q5 As we trace the ransomware's steps, a deeper verification is needed. Can you provide the sha256 hash of the ransomware's executable to cross-check with known malicious signatures?

![image](https://hackmd.io/_uploads/ByxrSH3ysbg.png)

Như đã phân tích ở câu trên thì hash sha256 của Ransomware đó là 
`b8d7fb4488c0556385498271ab9fffdf0eb38bb2a330265d9852e3a6288092aa`

[VirusTotal](https://www.virustotal.com/gui/file/b8d7fb4488c0556385498271ab9fffdf0eb38bb2a330265d9852e3a6288092aa/details)

>Flag: b8d7fb4488c0556385498271ab9fffdf0eb38bb2a330265d9852e3a6288092aa
---
#### Q6 One crucial piece remains: identifying the attacker's communication channel. Can you leverage threat intelligence and known Indicators of Compromise (IoCs) to pinpoint the ransomware author's onion domain?

[VirusTotal](https://www.virustotal.com/gui/file/b8d7fb4488c0556385498271ab9fffdf0eb38bb2a330265d9852e3a6288092aa/community)

[REvil-report](https://www.sophos.com/en-us/research/revil-sodinokibi-ransomware)

Qua tra cứu trên virustotal cùng các trang blog có report về ransomware này mình tim được cái onion domain của attacker đứng sau ransomware đó là

`http://aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion/{UID}`

![revil_06](https://hackmd.io/_uploads/SJb8l6ks-x.jpg)

>Flag: aplebzu47wgazapdqks6vrcv6zcnjppkbxbr6wketf56nf6aq2nmyoyd.onion