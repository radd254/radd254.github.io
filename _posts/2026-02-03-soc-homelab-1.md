---
layout: post
title: SOC Home Lab 1 - Setting up the environment
subtitle: Setting up the environment for the lab!
tags: [soc, splunk, ubuntu, fortigate, firewall]
comments: true
mathjax: true
author: Hoàng Nguyên Đạt
---
# SOC-Home-Lab-1

## Objective

The Lab project aimed to establish a controlled environment for simulating and detecting cyber attacks. The primary focus was to ingest and analyze logs within a Security Information and Event Management (SIEM) system, generating test telemetry to mimic real-world attack scenarios. This hands-on experience is set up a small virtual LAB to simulate real-world logging and monitoring scenarios, where we will collect logs from Apache web server and Fortigate firewall and send them to Splunk for storage, analysis, visualization and alerting.

### Skills Learned

- Good knowledge of how SIEM systems work and how to use them effectively.
- Skilled in reviewing and understanding network activity logs.
- Capable of identifying and creating patterns or signs of cyberattacks.
- Well-developed critical thinking and problem-solving abilities for cybersecurity challenges.

### Tools Used

- Security Information and Event Management (SIEM) system for log ingestion and analysis, in this lab I use Splunk.
- Firewall (Fortigate) to monitor, control traffic that incoming or outgoing and send to Splunk to analyse.

## Steps

1. SETUP

I created 2 Ubuntu VM on VMware and give it name is Splunk_Server and Apache_Server

Then I assgin static ip for those 2 VM like this below

![image](https://github.com/user-attachments/assets/f90813cf-403d-4e52-81eb-5e4bf6bba38c)

![image](https://github.com/user-attachments/assets/79ee8140-7bfc-4968-9aae-c57edd4898b2)

  *Assign static IP for 2 VM*


I also install Fortigate as a firewall to give more event to do

![Screenshot 2024-12-23 203815](https://github.com/user-attachments/assets/22ca66e1-72bb-4c6e-a037-26916554d4fa)

  *Seting up FotigateVM*

After that in Splunk_Server and Apache_Server I create a user name splunk to isolate the Splunk installation with the least privilege.

`useradd -s /bin/bash -d /opt/splunk -m splunk`

At the Splunk_SV VM I dowload the Splunk Enterprise at splunk website.

At the Apache_SV VM I dowload the Universal Forwarder.

Extract those file and run those Splunk and create account to use Splunk.

Now to recieve logs I need to add data-input to Splunk and config it.

![image](https://github.com/user-attachments/assets/e58b6343-84c4-48c2-9264-2a8d99f23e40)

![image](https://github.com/user-attachments/assets/db30c457-e2dc-4f53-ac9d-ca549a9f9585)

Because in Splunk for normal account I cant forward data throught port with 3 digit so I redirect that port to another port to bypass this.

Also in the Apache Server we need to config to be albe to send log to Splunk.

First I need dowload and enable apache2. After do that I can access the default page like this.

![image](https://github.com/user-attachments/assets/b5cf54b6-ffcf-40d9-bdb1-65cb73f35eec)

I creat some traffic to that page to get some log

![image](https://github.com/user-attachments/assets/94dc84fd-b1e2-4bcd-b435-ea4c942c8e3e)

![Screenshot 2024-12-23 211121](https://github.com/user-attachments/assets/5d2d79e5-79f6-4d0a-afa1-fffaf080401c)

We can see realtime traffic at the file `access.log` in the apache2 log folder

![Screenshot 2024-12-23 211634](https://github.com/user-attachments/assets/68011c61-e38d-487f-b0ca-f89af40c5316)

![Screenshot 2024-12-23 211140](https://github.com/user-attachments/assets/49df48ff-1d13-4b22-af2d-370a0af3b0e7)

Now to send those log to Splunk to analyze we need to config 2 file at the Apache Server like this.

![Screenshot 2024-12-23 214855](https://github.com/user-attachments/assets/8f17d7dc-f151-4251-a05b-c2b5f1a30589)

Then restart to save config.

![image](https://github.com/user-attachments/assets/881caade-91ba-4d7f-99da-9b1ef5b8173b)


2. ANALYZE LOGS

Log in Splunk I can do a lot of actions with that logs like

  - Create Reports

  ![Screenshot 2024-12-23 215403](https://github.com/user-attachments/assets/0975033d-a76e-41e5-9440-f778cb8e4122)

  - Create Dashboards

  ![Screenshot 2024-12-23 215740](https://github.com/user-attachments/assets/fd43a6b3-a055-48e8-9c69-385691034ca2)

  - Create Alerts

  ![Screenshot 2024-12-23 221054](https://github.com/user-attachments/assets/ac15008a-e1d4-4800-9f9b-53b7828205da)
  
  ![image](https://github.com/user-attachments/assets/c5acf025-6bcd-4d5d-bbed-ef08a877e24e)

  ![Screenshot 2024-12-23 221107](https://github.com/user-attachments/assets/2d58d8f2-3b54-4a52-bfae-c9c3fcdedd6a)


