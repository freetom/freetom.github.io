---
layout: post
title:  "Popcord root RCE"
date:   2019-09-14 11:33:37 +0100
categories: 0day
---

# CVE-2018-12072

[Description]
An issue was discovered in Cloud Media Popcorn A-200 03-05-130708-21-POP-411-000 firmware.
It is configured to provide TELNET remote access (without a password) that
pops a shell as root. If an attacker can connect to port 23 on the device, he can
completely compromise it.

------------------------------------------

[Vulnerability Type]
Incorrect Access Control

------------------------------------------

[Vendor of Product]
Cloud Media

------------------------------------------

[Affected Product Code Base]
Popcorn A-200 - Firmware 03-05-130708-21-POP-411-000

------------------------------------------

[Affected Component]
Popcorn A-200

------------------------------------------

[Attack Type]
Remote

------------------------------------------

[Impact Code execution]
true

------------------------------------------

[Impact Denial of Service]
true

------------------------------------------

[Impact Information Disclosure]
true

------------------------------------------

[Attack Vectors]
Remote TCP connections

------------------------------------------

[Discoverer]
Tomas Bortoli

------------------------------------------

[Reference]
http://support.cloudmedia.com
