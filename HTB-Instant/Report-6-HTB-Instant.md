# HTB Instant — Penetration Testing Assessment and Technical Walkthrough

> **Author:** matw0  
> **Assessment date:** 15–16 October 2026  
> **Target:** Hack The Box — Instant (retired Linux machine)  
> **Document:** Report 6 — CWES / CPTS / OSCP reporting practice  
> **Status:** Lab completed; evidence-based educational assessment  
> **Evidence standard:** Findings are based on the supplied Obsidian notes and three screenshots. Unrecorded steps are explicitly identified.

---

## 1. Executive Summary

An authorised security assessment was carried out against the retired Hack The Box machine **Instant**, a Linux host running a wallet-related application and an associated Android client. Testing began by downloading the Android APK and reviewing its decompiled Java code. The application exposed internal API hostnames and, more importantly, a **hard-coded administrator JSON Web Token (JWT)**. The token was accepted by the running backend and provided access to administrative API endpoints without first authenticating with an administrator's password.

Further testing identified a **path traversal vulnerability** in the administrative log-reading endpoint. By manipulating a filename parameter, it was possible to escape the intended log directory, read `/etc/passwd` and retrieve the SSH private key belonging to the local `shirohige` user. This provided an authenticated SSH foothold on the machine.

Local investigation identified the application's SQLite database, which had permissive file-mode bits and contained account information, password hashes and other sensitive fields. A password was recovered during the recorded testing using a Werkzeug-specific cracking tool. A Solar-PuTTY session backup was subsequently identified under `/opt/backups/Solar-PuTTY`; the recorded workflow shows that it was decrypted using a previously recovered password and revealed stored **root** credentials. Authentication with `su root` succeeded, establishing complete host compromise.

The most important risks demonstrated were **reusable privileged authentication material shipped inside a client application**, **insufficient filesystem path validation in an API**, and **recoverable privileged credentials in an accessible backup**. The SQLite permissions and password-strength observations warrant further validation before being treated as fully independent vulnerabilities.

### Outcome

- **Web/API phase:** administrator API access and arbitrary server-side file reading demonstrated.
- **User phase:** SSH login as `shirohige` demonstrated using an exposed private key.
- **Root phase:** root shell demonstrated using a credential recovered from a Solar-PuTTY session backup.
- **Disclosure note:** full JWTs, private keys, passwords, password hashes, database PINs, and HTB flags have been removed from this public-ready version.

---

## 2. Scope and Methodology

| Field | Details |
|---|---|
| Assessment type | Educational penetration-test assessment in an authorised retired HTB lab |
| Target | `instant.htb` |
| Discovered API hostname | `mywalletv1.instant.htb` |
| Discovered API documentation | `swagger-ui.instant.htb` |
| Application | Instant wallet web/API service and downloadable Android APK |
| Validated network services | HTTP API and SSH (through recorded access, not an attached port scan) |
| Operating system | Ubuntu 24.04.1 LTS, as reported by SSH login banner |
| Testing period | 15–16 October 2026 |
| Activities | APK decompilation, API testing, file-read validation, credential exposure analysis, local filesystem enumeration, offline credential recovery, privilege escalation and reporting |
| Exclusions | External production systems, unrelated domains and any destructive testing |

**Approach.** The testing began with client-side application analysis, continued with controlled requests to the API, and moved to local host investigation only after obtaining an SSH session. The following walkthrough records the sequence captured in the original report. Where a step was described but no raw transcript was attached, it is marked as such.

### Tools documented in the source notes

`jadx`, `curl`, `jq`, `ssh`, `sqlite3`, a Werkzeug-focused password recovery script and the Solar-PuTTY session decryption utility referenced in the original notes.

### Evidence IDs

| ID | Source evidence | What it demonstrates |
|---|---|---|
| E01 | `Pasted image 20261015121126.png` | The application's downloadable APK entry point |
| E02 | `Screenshot 2026-10-16 191337.png` | Decompiled APK references to API hostnames and routes |
| E03 | `Screenshot 2026-10-16 192057.png` | Swagger UI documenting exposed API routes |
| E04 | Original terminal notes | Successful API response using an APK-embedded administrator JWT |
| E05 | Original terminal notes | Traversal response containing `/etc/passwd` and a private SSH key |
| E06 | Original terminal notes | SSH authentication as `shirohige` |
| E07 | Original terminal notes | SQLite database permissions and user-table information |
| E08 | Original terminal notes | Offline password recovery; Solar-PuTTY backup analysis; successful `su root` |

> The source ZIP contains **three images** and a Markdown transcript. E04–E08 are recorded terminal evidence, **not screenshots**. Do not present them as screenshots taken during the engagement.

---

## 3. Technical Walkthrough

### 3.1 Application discovery and Android APK analysis

The initial application page provided a download for the Android package. Instead of treating the APK as a black box, I downloaded it and used `jadx` to inspect the Java source for API calls, route names and potentially sensitive values.

![Instant download page](./evidence/Pasted%20image%2020261015121126.png)

**Figure E01 —** Instant landing page with an Android download option.

```bash
jadx -d ~/Downloads/instant_source ~/Downloads/instant.apk
```

The recorded `jadx` run ended with **86 processing errors**. Despite this, relevant application classes were accessible, including `AdminActivities.java`, `LoginActivity.java`, `ProfileActivity.java` and `TransactionActivity.java`.

The `AdminActivities` code referenced the previously unknown endpoint:

```text
http://mywalletv1.instant.htb/api/v1/view/profile
```

More importantly, the request constructed in that class contained a **literal JWT value in its `Authorization` header**. The token's payload claimed an administrator role. The presence of an administrator token in a distributed mobile client is a finding; the hostname alone is useful reconnaissance, not necessarily a vulnerability.

The decompiled application also revealed `swagger-ui.instant.htb` in its network configuration. The hostnames were added to the lab resolver configuration so the relevant virtual hosts could be reached.

![APK references revealed in JADX](./evidence/Screenshot%202026-10-16%20191337.png)

**Figure E02 —** Decompiled application references revealing API requests and domain names. This is discovery evidence, not proof that the hostnames are inherently vulnerable.

### 3.2 Validating the embedded administrator token

A request was then sent to the profile endpoint using the token obtained from the APK. The backend returned HTTP **200** and a JSON object containing an administrator profile (`instantAdmin`) and the `Admin` role.

```bash
curl -s 'http://mywalletv1.instant.htb/api/v1/view/profile' \
  -H 'Authorization: <REDACTED_ADMIN_JWT>' | jq
```

**Relevant response excerpt:**

```json
{
  "Profile": {
    "username": "instantAdmin",
    "role": "Admin",
    "account_status": "active"
  },
  "Status": 200
}
```

The test therefore went beyond identifying a string in source code: it demonstrated that a privileged token distributed with the client application was **accepted by the server**.

> **Finding F01:** Hard-coded administrator authentication token (CWE-798).

### 3.3 Swagger API route enumeration

The documentation service at `swagger-ui.instant.htb` exposed API routes grouped under Users, Logs and Transactions. Of particular interest were the administrative log routes:

```text
GET /api/v1/admin/view/logs
GET /api/v1/admin/read/log
```

![Swagger documentation routes](./evidence/Screenshot%202026-10-16%20192057.png)

**Figure E03 —** Swagger interface showing documented API endpoints. An accessible Swagger page can be intentional; its visibility alone is not classified as a security defect here.

The documented endpoints were then examined using the administrator token. Listing logs returned a directory path and a single log entry:

```json
{
  "Files": ["1.log"],
  "Path": "/home/shirohige/logs/",
  "Status": 201
}
```

Reading `1.log` returned the expected sample content. This baseline confirmed that the log-reading endpoint worked normally before testing whether its filename restriction could be bypassed.

### 3.4 Path traversal and arbitrary file read

The `log_file_name` parameter was modified to include parent-directory references. Instead of restricting reads to the log directory, the server resolved the supplied path and returned content from elsewhere on the filesystem.

**Request demonstrating the boundary failure:**

```bash
curl -s \
  'http://mywalletv1.instant.htb/api/v1/admin/read/log?log_file_name=../../../../../etc/passwd' \
  -H 'Authorization: <REDACTED_ADMIN_JWT>' | jq
```

**Relevant response excerpt:**

```json
{
  "/home/shirohige/logs/../../../../../etc/passwd": [
    "root:x:0:0:root:/root:/bin/bash\n",
    "shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash\n"
  ],
  "Status": 201
}
```

The test was repeated with files associated with the identified local user. The endpoint returned the SSH `authorized_keys` content and subsequently the contents of the private key file at:

```text
/home/shirohige/logs/../.ssh/id_rsa
```

The private key itself is **not reproduced** in this report. Its disclosure is the most significant impact of this vulnerability because it allowed the web-based file-reading issue to be converted into authenticated host access.

> **Finding F02:** Path traversal allowing arbitrary local file read (CWE-22).

### 3.5 Initial host access via SSH

After extracting the exposed SSH private key, the key was saved locally with restricted permissions and used to authenticate to the host.

```bash
chmod 600 id_rsa
ssh -i id_rsa shirohige@instant.htb
```

The SSH service accepted the key and opened an interactive shell under `shirohige`. The banner identified the host as Ubuntu 24.04.1 LTS. The user's HTB flag was subsequently accessible, confirming the lab's user stage, but the flag is intentionally omitted.

**Why this matters:** There is a clear distinction between **arbitrary file read** and **remote code execution**. The API did not need to execute a shell command. It exposed an SSH authentication secret, and that separate service then provided authenticated system access.

### 3.6 SQLite database and local configuration inspection

With local access established, the application files were investigated under:

```text
/home/shirohige/projects/mywallet/Instant-Api/mywallet/
```

Reviewing `app.py` showed that the application used SQLAlchemy with the database URI:

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instant.db'
```

The resulting database was located in the `instance/` directory. A permission check returned:

```text
-rw-r--r-- 1 shirohige shirohige 36864 Sep 30 2024 instant.db
```

The `0644` mode means that the file has its owner read/write bits set and its group/other read bits set. This is a potential exposure of sensitive application data.

**Evidence limitation:** The transcript shows the owner account (`shirohige`) reading its own file. It does **not** show a different, unauthorised local account traversing the enclosing directories and reading the database. The security impact of the permissions should therefore be described as **provisional until an independent local access check is completed**.

The original `cat` output was difficult to interpret because SQLite stores structured binary data. Reopening the saved database using `sqlite3` was a better way to examine the application schema and user records:

```sql
.tables
SELECT username, role FROM wallet_users;
SELECT username, password FROM wallet_users WHERE username = 'instantAdmin';
```

The account table contained user identifiers and **PBKDF2-SHA256 password hashes**, as well as fields for wallet identifiers, `secret_pin` values, roles and account status. No full password hashes, PINs or invite tokens are reproduced here.

> **Finding F03 (verification required):** Potentially over-permissive SQLite database permissions (CWE-732).

### 3.7 Password recovery and Solar-PuTTY session backup

The recorded testing examined the application's hashing implementation and identified Werkzeug's `generate_password_hash` mechanism. A Werkzeug-specific recovery utility was then run against a password hash obtained from the database:

```bash
python3 werkzeug_cracker.py -w /usr/share/wordlists/rockyou.txt -p hash.txt
```

The tool reported that a password had been recovered. The value is redacted here.

This shows that at least one sampled password was susceptible to a wordlist-based attack. **It does not establish that PBKDF2-SHA256 is inherently insecure**, nor does it prove that the entire application's password policy is weak. That distinction is important when classifying findings.

Further local enumeration revealed a Solar-PuTTY session archive:

```text
/opt/backups/Solar-PuTTY/sessions-backup.dat
```

The notes record that the backup was decrypted using a previously recovered password and a Windows-compatible Solar-PuTTY decryption utility. The resulting JSON data contained a credential entry named `instant-root`, associated with the `root` account.

```json
{
  "CredentialsName": "instant-root",
  "Username": "root",
  "Password": "<REDACTED_ROOT_PASSWORD>"
}
```

**Evidence limitation:** The original notes do not contain the complete command and tool-output transcript for decrypting the `.dat` file. They do contain the relevant extracted JSON field and the subsequent successful authentication as root. The decryption step is therefore **described from the user's recorded workflow, not presented as an independently captured command sequence**.

> **Finding F04:** Insufficient protection of privileged credentials in a recoverable session backup (CWE-522 / CWE-922).

### 3.8 Privilege escalation and proof of compromise

With the root password recovered from the Solar-PuTTY backup, the assessment attempted to change users from the `shirohige` session:

```bash
su root
```

The command succeeded, and the next prompt showed `root@instant`. Access to the protected `/root` directory was demonstrated in the supplied terminal notes. The HTB root flag was retrieved during the lab, but **its value is excluded from this report**.

The complete attack progression was therefore:

```text
Downloadable Android APK
    ↓  client-side decompilation
Embedded privileged JWT
    ↓  authenticated administrator API requests
Log-reading endpoint with path traversal
    ↓  SSH private key disclosure
SSH login as shirohige
    ↓  local application and backup enumeration
Recoverable Solar-PuTTY session credentials
    ↓  su root
Root-level access
```

---

## 4. Findings Summary

| ID | Finding | Severity | CVSS v3.1 | CWE | Evidence status |
|---|---|---|---|---|---|
| **F01** | Hard-coded administrator JWT in distributed APK | **High** | **7.5** | CWE-798 | Verified by live API response |
| **F02** | Path traversal / arbitrary local file read in log endpoint | **Medium** *(standalone)* | **4.9** | CWE-22 | Verified by `/etc/passwd` and SSH-key disclosures |
| **F03** | Potentially over-permissive SQLite file permissions | **Medium, provisional** | **5.5, conditional** | CWE-732 | Mode confirmed; cross-user accessibility unverified |
| **F04** | Privileged credentials recoverable from accessible backup | **High** | **7.0** | CWE-522, CWE-922 | Credential extraction described; root authentication verified |

**Scoring note:** These are analyst-assigned **CVSS v3.1 Base Scores**, not official HTB ratings. F02 requires administrator privileges **when scored on its own**; the exploit chain becomes substantially more serious because F01 supplies those privileges. F03's score is illustrative and should not be treated as verified without demonstrating unauthorised access. F04 uses `AC:H` to reflect the additional offline password-recovery condition observed in this assessment.

### 4.1 F01 — Hard-coded administrator JWT in Android client

| Field | Value |
|---|---|
| Severity | **High — 7.5** |
| CVSS v3.1 vector | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| CWE | **CWE-798 — Use of Hard-coded Credentials** |
| CVE | **N/A — no applicable published identifier established** |
| Affected component | Downloadable Android APK, `AdminActivities.java` |
| Affected API | `mywalletv1.instant.htb` |
| Preconditions | Ability to obtain and inspect the APK; no prior administrator account required |
| Evidence | E01, E02, E04 |

**Description.** A usable privileged JWT was embedded as a constant in Android client code. Anyone with access to the distributed APK could recover the token by inspecting its compiled application resources. Testing confirmed that the server accepted the token and returned administrator profile information.

**Proof of concept.** The tester decompiled the application with `jadx`, identified the header value in `AdminActivities.java`, and reused it in an authorised request to `/api/v1/view/profile`. The response confirmed a privileged `Admin` account and HTTP status 200. The original token is intentionally redacted.

**Impact.** Disclosure of a valid administrator token undermines the application's authentication boundary. An unauthenticated party able to obtain the APK could impersonate the embedded administrator identity and access API functionality intended for privileged users. Additional administrative routes were exposed in the documentation; the recorded tests confirm read access, not an exhaustive assessment of every possible modification operation.

**Remediation.** Never include fixed privileged session tokens, service-account credentials or long-lived signing secrets in software distributed to clients. Issue short-lived, user-specific tokens after proper authentication; enforce role and object authorisation on every backend endpoint; revoke the embedded token and rotate any related credentials. Review token expiry and revocation handling. Prefer TLS for all authenticated API traffic.

**Fix validation.** Decompile a newly distributed APK and confirm no privileged reusable token is present. Retry the previous token and verify rejection. Confirm that protected API routes reject requests without a freshly issued authorised session.

### 4.2 F02 — Path traversal in administrative log-reading API

| Field | Value |
|---|---|
| Severity | **Medium — 4.9 (standalone)** |
| CVSS v3.1 vector | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N` |
| CWE | **CWE-22 — Improper Limitation of a Pathname to a Restricted Directory** |
| Related CWE | CWE-200 — Exposure of Sensitive Information |
| CVE | **N/A — custom application weakness** |
| Affected endpoint | `GET /api/v1/admin/read/log` |
| Affected parameter | `log_file_name` |
| Preconditions | Administrative API authorisation; satisfied in this lab by F01 |
| Evidence | E03, E05, E06 |

**Description.** The administrative log-reading endpoint accepted relative path components in the `log_file_name` query value. The backend read from a path constructed relative to `/home/shirohige/logs/` without enforcing a secure boundary that confined access to approved log files.

**Proof of concept.** The normal `1.log` value returned sample log content. The parameter was then changed to `../../../../../etc/passwd`, and the API returned operating-system account records. A follow-up read of `../.ssh/id_rsa` returned the `shirohige` user's private SSH key. Full key contents are omitted.

**Impact.** An authorised API user could read files outside the log directory within the permissions available to the server-side process. In this case, the disclosure included a usable SSH authentication secret and enabled an interactive shell as `shirohige`. The **standalone** CVSS rating reflects the administrative privilege requirement; the **combined F01 + F02 chain** should be treated as a high-priority compromise path.

**Remediation.** Do not accept filesystem paths directly from API clients. Use a server-side allowlist or opaque identifier for known log files. Resolve and canonicalise candidate paths, verify they remain within the permitted directory, reject traversal components, and restrict the service account's filesystem read permissions. Protect user home directories and SSH keys from unrelated processes.

**Fix validation.** Confirm approved log entries can be read and that `../` sequences, encoded traversal variants, absolute paths and symbolic-link escapes cannot return files outside the intended log directory.

### 4.3 F03 — Potentially over-permissive SQLite database permissions

| Field | Value |
|---|---|
| Severity | **Provisional Medium — 5.5, subject to verification** |
| Conditional CVSS vector | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| CWE | **CWE-732 — Incorrect Permission Assignment for Critical Resource** |
| Related CWE | CWE-200 — Exposure of Sensitive Information |
| CVE | **N/A — file permission/configuration issue** |
| Affected resource | `/home/shirohige/projects/mywallet/Instant-Api/mywallet/instance/instant.db` |
| Evidence | E07 |

**Description.** The SQLite database containing wallet and account information had file permissions `-rw-r--r--` (`0644`). The database included sensitive fields such as username, email, wallet identifiers, password hashes, invite tokens and transaction data.

**Proof of concept.** `ls -l instant.db` showed its permission bits; the file's contents were later examined with `sqlite3`, demonstrating sensitive application records.

**Important qualification.** The observed shell session belonged to `shirohige`, who also owned the database file. The `0644` bits indicate that other users would have file-level read permission, **but directory traversal permissions and access from a separate local security principal were not recorded**. This finding should remain provisional until that question is tested. It would be incorrect to claim that unauthorised users definitively accessed the file based only on the present transcript.

**Potential impact.** If other local accounts can reach the file, they may obtain password hashes, authentication tokens, PINs and wallet records, supporting account compromise or further attacks. The source material does not demonstrate modifying the database as another user.

**Remediation.** Use an application-specific service account and restrict database permissions to the minimal operational set, commonly `0600` or `0640` with a dedicated group when justified. Restrict permissions on all ancestor directories and protect copies, backups and snapshots. Review exposed tokens and secrets for rotation.

**Fix validation.** Confirm the application still operates with the tighter permissions. Then test database access as a deliberately separate, unprivileged account (with authorisation in the lab) to establish that the file and its directory path are inaccessible.

### 4.4 F04 — Recoverable root credentials stored in Solar-PuTTY backup

| Field | Value |
|---|---|
| Severity | **High — 7.0** |
| CVSS v3.1 vector | `CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| CWE | **CWE-522 — Insufficiently Protected Credentials**; **CWE-922 — Insecure Storage of Sensitive Information** |
| CVE | **N/A — no specific product CVE established by the recorded evidence** |
| Affected file | `/opt/backups/Solar-PuTTY/sessions-backup.dat` |
| Preconditions | Local account able to obtain the backup plus the backup's decryption password |
| Evidence | E08 |

**Description.** The machine retained a Solar-PuTTY backup containing privileged connection credentials. The file was available during low-privileged local enumeration, and the recorded assessment describes using a previously recovered password to decrypt it. The resulting JSON record disclosed a password associated with the `root` account.

**Proof of concept.** The backup was identified at `/opt/backups/Solar-PuTTY/sessions-backup.dat`. The tester described decrypting the archive using a Windows-compatible Solar-PuTTY utility; the saved notes include an extracted `CredentialsName: instant-root` record and `Username: root`. The complete decryptor invocation was not recorded. A subsequent `su root` succeeded and the prompt changed to `root@instant`, establishing that the disclosed credential enabled escalation.

**Impact.** Once the backup and its decryption password were obtained, an ordinary local user could recover a privileged credential and gain root-level control. This is a credential management and filesystem trust-boundary failure. The presence of encryption is not itself a security defect; the issue is that the backup was accessible and decryptable within the attacker's context, and it contained an account credential with excessive privilege.

**Remediation.** Remove unnecessary privileged credentials from exported connection-profile backups. Move credential storage to an approved secret manager with independent access controls, prevent standard users from reading administrative backup archives, use strong and unique encryption passphrases, and prohibit reuse of account passwords for backup encryption. Rotate exposed root credentials and favour tightly controlled administrative escalation over direct password reuse.

**Fix validation.** Confirm the backup is inaccessible to the tested low-privileged user, verify that exported sessions contain no recoverable root password, and test that the previously exposed credential can no longer be used with `su` or other authentication mechanisms.

---

## 5. Additional Observations — Not Standalone Confirmed Findings

### A. Embedded or discoverable hostnames

The APK referenced `mywalletv1.instant.htb` and `swagger-ui.instant.htb`. These names significantly improved enumeration, but embedding server URLs in a mobile client is often necessary for the application to function. **Do not classify the existence of hostnames as source-code disclosure or a vulnerability without demonstrating a separate security impact.** In this assessment, the actual client-side flaw was the hard-coded administrator token.

### B. Wordlist-recoverable password

The supplied notes show a password recovered using a Werkzeug-focused tool and a common wordlist. That supports an observation that **the recovered password was guessable under the tested conditions**. It does not, on its own, prove a missing password-strength policy or establish that the PBKDF2-SHA256 algorithm was weak. Strong password rules, unique backup passphrases, MFA where appropriate and credential-rotation controls are sensible mitigations. Reassess as a separate finding if future testing demonstrates a broader policy weakness or widespread reuse.

### C. Broad `shirohige` developer/application access

The compromised local account could inspect its home-directory application source, database and backup-related material. Since the application files and database were under the user's own directory, some access may have been intended. **There is no recorded evidence of developer-group membership, separate group access, or a demonstrated privilege boundary crossed solely by reading the application's source.** A better recommendation is to separate deployment/service identities, restrict sensitive material, and prevent any user with only a web foothold from obtaining usable operating-system credentials.

### D. Plain HTTP in APK URLs

The recorded APK strings and tester requests use `http://` for authenticated API communications. This raises a potential **CWE-319 — Cleartext Transmission of Sensitive Information** concern, but no packet capture or transport-policy test was attached. Do not automatically label it a verified network eavesdropping finding without checking how the client and server behave in the intended deployment. Move authentication traffic to TLS and reject cleartext authentication requests.

---

## 6. Prioritised Remediation Plan

| Priority | Recommendation | Addresses |
|---|---|---|
| **1 — Immediate** | Revoke the embedded administrator JWT, remove it from client builds, introduce properly issued short-lived tokens | F01 |
| **1 — Immediate** | Correct log-read path handling and limit the API process's filesystem access | F02 |
| **1 — Immediate** | Remove stored root credentials from user-reachable backups; rotate exposed administrative secrets | F04 |
| **2 — High** | Enforce least-privilege separation between web processes, developer accounts, application data and backup stores | F02, F03, F04 |
| **2 — High** | Audit database file and directory permissions from another ordinary user account; tighten where required | F03 |
| **2 — High** | Review credential strength and reuse and eliminate cleartext authenticated API traffic | Additional observations |

---

## 7. Conclusion

Instant demonstrated how a comparatively small client-side mistake can lead to a much larger compromise. Decompiling the APK did not directly grant a shell, but it exposed a reusable administrator token that allowed access to backend administrative routes. A separate path traversal flaw then allowed server-side files to be read, including an SSH private key, turning API access into a local user foothold.

Once on the system, the assessment moved from web testing to traditional Linux enumeration and credential analysis. The application's SQLite database and its password storage were investigated, and a recoverable Solar-PuTTY backup ultimately exposed a root credential. The recorded `su root` result confirmed full compromise of the HTB host.

The main lesson is the importance of treating an attack path as **several linked vulnerabilities**, each with its own root cause and remediation. A good penetration-test report should explain not only *what worked*, but *why it worked*, which boundary was crossed, what evidence proves it, and what must change to prevent recurrence.

---

## 8. Reporting Notes and Limitations

1. **Only three screenshots** were supplied. The most important exploitation evidence is preserved in the original terminal transcripts; add screenshots or saved request/response files for the key API tests on future engagements.
2. **No independent Nmap transcript** was supplied. HTTP and SSH were verified through use, but no port-scan output is attributed to this engagement.
3. **Password cracking and Solar-PuTTY decryption** are described in the supplied notes, but the full decryptor command and output were not captured. Do not fabricate them.
4. **World-readable mode bits do not by themselves prove cross-user access.** The enclosing directory permissions and an independent-user test would be needed to confirm F03's practical exploitability.
5. **No applicable CVE** has been established for the custom Instant weaknesses or the backup-storage issue described here. CWE classifies the weakness; CVSS assesses its severity; a CVE is a specific published vulnerability record and should not be invented.
6. **CVSS is contextual.** F01–F04 scores are analyst estimates for the isolated weaknesses. The complete chain is more serious than the individual standalone score for the administrative log endpoint.
7. **Redaction:** JWTs, password hashes, SSH private keys, database PINs, admin credentials and HTB flags have been removed from the report text. The original screenshot filenames are unchanged.

### References

- [FIRST — CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [MITRE — CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [MITRE — CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [MITRE — CWE-732: Incorrect Permission Assignment for Critical Resource](https://cwe.mitre.org/data/definitions/732.html)
- [MITRE — CWE-522: Insufficiently Protected Credentials](https://cwe.mitre.org/data/definitions/522.html)
- [MITRE — CWE-922: Insecure Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/922.html)

*External references support vulnerability terminology and scoring concepts; the technical walkthrough is grounded in the supplied assessment notes and screenshots.*
