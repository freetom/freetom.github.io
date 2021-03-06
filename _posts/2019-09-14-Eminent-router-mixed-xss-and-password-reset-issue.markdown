---
layout: post
title:  "Eminent router mixed XSS and password reset issue"
date:   2019-09-14 11:33:37 +0100
categories: 0day
---

<style>
        code {
        white-space: pre-wrap;
        }
</style>

# CVE-2018-10719

```
[Description]

An issue was discovered on Eminent EM4544 9.10 devices.
Stored Cross-Site-Scripting has been found on the web interface. The
'timepro.cgi' endpoint allows injections of JavaScript through the
'name' GET parameter. The injection is stored as part of a
port-forwarding rule and therefore it will persist after system
restart.

------------------------------------------

[Additional Information]

PoC link: http://192.168.8.1/cgi-bin/timepro.cgi?tmenu=natrouterconf&smenu=portforward&act=add_pf&nf_rule_count=1&rule_index=&rule=5&sel_server=0&name='><script>alert(1)</script>&os_ip1=192&os_ip2=168&os_ip3=8&os_ip4=34&protocol=tcp&i_port1=1&i_port2=1&o_port1=1&o_port2=1
------------------------------------------

[Vulnerability Type]

Cross Site Scripting (XSS)

------------------------------------------

[Vendor of Product]

Eminent

------------------------------------------

[Affected Product Code Base]

EM4544 - 9.10

------------------------------------------

[Affected Component]

Eminent Router EM4544

------------------------------------------

[Attack Type]

Remote

------------------------------------------

[Impact Code execution]

true

------------------------------------------

[Attack Vectors]

Malicious link that once opened by an a user authenticated to the router triggers the stored Cross-Site-Scripting

------------------------------------------

[Discoverer]

Tomas Bortoli

------------------------------------------

[Reference]

http://www.eminent-online.com/faq/index/faq

```

# CVE-2018-10720

```
[Description]

An issue was discovered on Eminent EM4544 9.10 devices.
Reflected Cross-Site-Scripting has been found on the web interface. The 'timepro.cgi' endpoint allows injections of JavaScript
through the 'wan_name' GET parameter.

------------------------------------------

[Additional Information]

PoC link: http://192.168.8.1/cgi-bin/timepro.cgi?tmenu=iframe&smenu=pppoe_sched&wan_name=wan1g0rl2%22%3E%3Cscript%3Ealert(1)%3C%2fscript%3E

------------------------------------------

[Vulnerability Type]

Cross Site Scripting (XSS)

------------------------------------------

[Vendor of Product]

Eminent

------------------------------------------

[Affected Product Code Base]

EM4544 - 9.10

------------------------------------------

[Affected Component]

Eminent Router EM4544

------------------------------------------

[Attack Type]

Remote

------------------------------------------

[Impact Code execution]

true

------------------------------------------

[Attack Vectors]

Malicious link that once opened by an a user authenticated to the router triggers the reflected Cross-Site-Scripting

------------------------------------------

[Discoverer]

Tomas Bortoli

------------------------------------------

[Reference]

http://www.eminent-online.com/faq/index/faq
```

# CVE-2018-10765

```
[Suggested description]

An issue was discovered on Eminent EM4544 9.10 devices.
Reflected Cross-Site-Scripting has been found on the web interface. The
'timepro.cgi' endpoint allows injections of JavaScript through the
'tmenu' GET parameter under certain conditions.

------------------------------------------

[Additional Information]

Link PoC: http://192.168.8.1/cgi-bin/timepro.cgi?saveconfig=1&tmenu='><script>alert(1)</script>&amp;smenu=asd

------------------------------------------

[Vulnerability Type]

Cross Site Scripting (XSS)

------------------------------------------

[Vendor of Product]

Eminent

------------------------------------------

[Affected Product Code Base]

EM4544 - 9.10

------------------------------------------

[Affected Component]

Eminent Router EM4544

------------------------------------------

[Attack Type]

Remote

------------------------------------------

[Impact Code execution]

true

------------------------------------------

[Attack Vectors]

Malicious link that once opened by a user authenticated to the router triggers the reflected Cross-Site-Scripting

------------------------------------------

[Discoverer]
Tomas Bortoli
```

# CVE-2018-10766

```
[Suggested description]

An issue was discovered on Eminent EM4544 9.10 devices.
Reflected Cross-Site-Scripting has been found on the web interface. The
'timepro.cgi' endpoint allows injections of JavaScript through the
'smenu' GET parameter under certain conditions.

------------------------------------------

[Additional Information]

Link PoC: http://192.168.8.1/cgi-bin/timepro.cgi?saveconfig=1&tmenu=system&smenu=info'><script>alert(1)</script>

------------------------------------------

[Vulnerability Type]

Cross Site Scripting (XSS)

------------------------------------------

[Vendor of Product]

Eminent

------------------------------------------

[Affected Product Code Base]

EM4544 - 9.10

------------------------------------------

[Affected Component]

Eminent Router EM4544

------------------------------------------

[Attack Type]

Remote

------------------------------------------

[Impact Code execution]

true

------------------------------------------

[Attack Vectors]

Malicious link that once opened by a user authenticated to the router triggers the reflected Cross-Site-Scripting

------------------------------------------

[Discoverer]

Tomas Bortoli
```


# CVE-2018-12073

```
[Description]

An issue was discovered on Eminent EM4544 9.10 devices.
The device does not require the user's current password to set a new
one within the web interface. Therefore, it is possible to exploit
this issue (e.g., in combination with a successful XSS, or at an unattended workstation) to change the
admin password to an attacker-chosen value without knowing the
current password.

------------------------------------------

[VulnerabilityType Other]

Insecure password management

------------------------------------------

[Vendor of Product]

Eminent

------------------------------------------

[Affected Product Code Base]

EM4544 - 9.10

------------------------------------------

[Affected Component]

EM4544 - 9.10

------------------------------------------

[Attack Type Other]

Bad password management

------------------------------------------

[CVE Impact Other]

Change password without knowing the current one

------------------------------------------

[Attack Vectors]

Web interface, change password

------------------------------------------

[Has vendor confirmed or acknowledged the vulnerability?]

true

------------------------------------------

[Discoverer]

Tomas Bortoli

------------------------------------------

[Reference]

http://www.eminent-online.com/eminent-em4544-pro-wireless-300n-router.html
```
