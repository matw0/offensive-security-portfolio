# Report 4 — HTB Gavel | Penetration Testing Assessment

> [!info] Assessment status
> **Training assessment:** Retired Hack The Box (HTB) laboratory machine. This document is a CWES-style practice report, not an assessment of a production system.
> 
> **Evidence note:** Screenshot links point to the **`evidence/` subfolder** beside this Markdown file. All original screenshot filenames are preserved; none has been renamed. Five referenced images were not included in the supplied ZIP (listed in [Evidence checklist](#evidence-checklist-before-publication)). They may still exist in the original Obsidian vault.

## 1. Executive Summary

A security assessment was conducted against the retired Hack The Box machine **Gavel**, a Linux-based system hosting a PHP auction application.

Testing identified an exposed Git repository that disclosed application source code, followed by a SQL injection vulnerability within the inventory functionality. The SQL injection enabled unauthorised extraction of user account information, including password hashes.

Following recovery of a privileged account password, access was obtained to the application's administration panel. Insufficient controls over dynamically executed auction rules subsequently allowed server-side PHP code execution, resulting in a shell operating under the `www-data` account.

Further local enumeration identified a privileged daemon responsible for processing user-supplied YAML submissions. Testing revealed a path by which this functionality could be abused to access root-protected information. **The precise configuration-bypass sequence should be documented before the privilege-escalation finding is treated as fully reproduced.**

The identified weaknesses demonstrate how information disclosure, unsafe database query construction and insecure execution of user-controlled code can be combined to compromise an application and its supporting host.

## 2. Assessment Scope

| Field | Details |
| --- | --- |
| Environment | Hack The Box — Gavel (retired machine) |
| Target hostname | `gavel.htb` |
| Operating system | Ubuntu Linux |
| Services identified | SSH (22/tcp), HTTP (80/tcp) |
| Assessment dates | 6–7 October 2026 |
| Testing approach | Black-box testing supplemented by recovered source-code analysis |
| Authorisation | Authorised Hack The Box laboratory environment |
| Main testing areas | Web enumeration, source-code disclosure, SQL injection, code injection, local privilege escalation |

The assessment was confined to the provided HTB machine. No external production systems were tested. Sensitive authentication material and machine flags should be redacted from any publicly distributed version.

## 3. Methodology

Testing followed a structured methodology beginning with network and service discovery, followed by web application enumeration and source-code analysis.

Potential weaknesses were investigated through manual testing and supporting tools, including **Nmap, ffuf, Burp Suite, SQLMap and Hashcat**. Confirmed findings were evaluated according to the access required, security impact and available supporting evidence.

Post-exploitation testing was undertaken to evaluate the effect of compromised application privileges and identify opportunities for further privilege escalation.

Findings were classified using **CWE identifiers** and assessed using **CVSS v3.1**, with remediation recommendations focused on addressing the underlying root causes.

### 3.1 Initial enumeration

The initial Nmap scan identified OpenSSH on port 22 and Apache HTTP on port 80. The HTTP service redirected to `gavel.htb`, which was resolved locally for testing. The initial target address in the original notes was `10.129.82.14`; a later shell transcript showed a different lab IP. If the machine was reset between sessions, this should be recorded in the final evidence log.

```text
22/tcp open  ssh   OpenSSH 8.9p1 Ubuntu
80/tcp open  http  Apache httpd 2.4.52
HTTP redirect: http://gavel.htb/
```

![Pasted image 20261006202445.png](./evidence/Pasted%20image%2020261006202445.png)

An application account was created to examine authenticated features such as auctions and inventory. The researcher inspected bidding requests and attempted an automated SQL injection test against the login form; that attempt **did not identify an injectable parameter**, and is therefore not counted as a finding.

![Pasted image 20261006205837.png](./evidence/Pasted%20image%2020261006205837.png)

![Pasted image 20261006210256.png](./evidence/Pasted%20image%2020261006210256.png)

![Pasted image 20261006210407.png](./evidence/Pasted%20image%2020261006210407.png)

![Pasted image 20261006210519.png](./evidence/Pasted%20image%2020261006210519.png)

## 4. Summary of Findings

| ID | Finding | CWE | Proposed CVSS v3.1 | Severity |
| --- | --- | --- | --- | --- |
| F01 | Exposed Git repository and source-code disclosure | CWE-552 | 5.3 | Medium |
| F02 | SQL injection through unsafe PDO query construction | CWE-89 | 6.5 | Medium |
| F03 | PHP code injection through auction rule processing | CWE-94 | 7.2 | High |
| F04 | Privileged code execution through insecure YAML rule processing | CWE-94 / CWE-269 | 7.8 (provisional) | High |

> [!note] Scoring and identifiers
> Scores are **analyst assessments**, not official HTB severity ratings. CVSS vectors must be reassessed if verified privileges, complexity, scope or impact differ. No applicable CVE was established from the supplied evidence; **CVE: N/A** does **not** mean the issue is harmless. CVE (an individual disclosed vulnerability), CWE (a class of weakness), CVSS (a severity assessment) and PoC (evidence demonstrating a vulnerability) are distinct concepts.

---

## 5. Detailed Findings

### F01 — Exposed Git Repository and Source-Code Disclosure

| Field | Value |
| --- | --- |
| **Severity** | **Medium — 5.3** |
| **CVSS v3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **CWE** | CWE-552 — Files or Directories Accessible to External Parties |
| **CVE** | N/A — no applicable CVE established |
| **Affected asset** | `http://gavel.htb/.git/` |
| **Access required** | Unauthenticated |

#### Description

During directory enumeration, the web server was found to expose Git repository files through the publicly accessible HTTP service.

The exposed repository allowed application source files to be recovered and examined, revealing internal PHP application logic, database interaction patterns and privileged administrative functionality.

#### Evidence / Proof of Concept

The `ffuf` output showed successful responses for `.git/HEAD` and further repository paths, including `.git/config`, `.git/index` and repository objects. The repository was then recovered with a Git-dumping tool and inspected locally.

```text
.git/HEAD             [Status: 200]
.git/config           [Status: 200]
.git/index            [Status: 200]
```

The recovered application contained files such as `inventory.php`, `admin.php` and `bidding.php`, which were subsequently analysed for vulnerabilities.

#### Impact

An unauthenticated attacker could retrieve internal application source code, potentially revealing sensitive implementation details and assisting the discovery of additional vulnerabilities.

#### Remediation

- Remove `.git` metadata from the deployed web directory and deny HTTP access to version-control paths.
- Publish only the application files required in production through a controlled deployment process.
- Review exposed repository history for credentials or other secrets and rotate any confirmed compromised values.
- Verify remediation by requesting previously exposed paths and confirming they are no longer externally accessible.

---

### F02 — SQL Injection Through Unsafe PDO Query Construction

| Field | Value |
| --- | --- |
| **Severity** | **Medium — 6.5** |
| **CVSS v3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-89 — Improper Neutralization of Special Elements used in an SQL Command |
| **CVE** | N/A — no applicable CVE established |
| **Affected endpoint** | `inventory.php` |
| **Affected parameters** | `sort`, `user_id` |
| **Access required** | Authenticated application session |

#### Description

Source-code analysis identified unsafe construction of an SQL statement within the inventory functionality.

Although the query uses a PDO prepared statement for the user identifier, part of the SQL statement is dynamically constructed using a column selection value. Manipulation of inventory parameters allowed the intended query structure to be altered, resulting in unauthorised access to data from the application's user database.

#### Evidence / Proof of Concept

A bid was placed so that an item appeared in the authenticated inventory. The `Sort By` function exposed the `sort` parameter, while the request also included a `user_id` parameter.

![Pasted image 20261006221907.png](./evidence/Pasted%20image%2020261006221907.png)

![Pasted image 20261006221928.png](./evidence/Pasted%20image%2020261006221928.png)

![Pasted image 20261006222342.png](./evidence/Pasted%20image%2020261006222342.png)

![Pasted image 20261006222303.png](./evidence/Pasted%20image%2020261006222303.png)

The relevant application source included the following query construction:

```php
$stmt = $pdo->prepare(
    "SELECT $col FROM inventory WHERE user_id = ? ORDER BY item_name ASC"
);
$stmt->execute([$userId]);
```

A crafted inventory request manipulating `user_id` and `sort` resulted in a response containing usernames and bcrypt password-hash values, including data associated with the privileged `auctioneer` account. The recovered secrets should be **redacted** in a publicly distributed report.

![Pasted image 20261006230752.png](./evidence/Pasted%20image%2020261006230752.png)

The original notes also record an unsuccessful automated SQL injection attempt. That negative test does not invalidate the later manually demonstrated data disclosure.

#### Root-Cause Explanation — PDO and Query Structure

Prepared statements are not inherently unsafe. Binding `$userId` as a value would normally protect that value against injection; however, the query also interpolates the `$col` SQL identifier directly into the statement. Identifiers require a trusted allowlist rather than normal value placeholders.

The source notes discuss a PDO **emulated-prepares parser interaction** as part of the machine's exploit, alongside manipulation of the inventory parameters. The exact internal lexer behaviour was **not independently traced** in the supplied testing evidence. The report should therefore avoid presenting a particular null-byte parsing mechanism as independently verified unless the precise successful HTTP request confirms it.

#### Impact

An authenticated attacker could retrieve sensitive database records, including account credentials in hashed form. Where an exposed password is guessable and subsequently recovered, the attacker may gain access to privileged application features.

> [!important] Hash interpretation
> A `$2y$10$` hash indicates **bcrypt with cost 10**. The demonstrated concern was a recoverable/guessable **password**, not proof that bcrypt itself is broken. This distinction matters when describing root cause and remediation.

#### Remediation

- Use a strict server-side allowlist for permitted sort columns and reject unexpected identifiers.
- Bind all query **values** using native prepared statements; review the use of PDO emulated prepares.
- Enforce server-side authorisation to prevent retrieval of another user's inventory or account data.
- Restrict database privileges according to least privilege.
- Require strong passwords and review privileged accounts affected by credential disclosure.
- Retest by replaying the original request and confirming it cannot alter the intended query or disclose unrelated records.

---

### F03 — PHP Code Injection Through Auction Rule Processing

| Field | Value |
| --- | --- |
| **Severity** | **High — 7.2** |
| **CVSS v3.1 vector** | `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-94 — Improper Control of Generation of Code |
| **CVE** | N/A — no applicable CVE established |
| **Affected functionality** | Auction administration and bid processing |
| **Affected parameter** | `rule` |
| **Access required** | Privileged `auctioneer` session |

#### Description

The auction administration interface allows a privileged user to modify rules associated with active auctions. These rules are subsequently interpreted as executable PHP code by the application's bid-processing functionality.

This creates a code-injection vulnerability because attacker-controlled rule content can be executed by the server rather than being treated as ordinary application data.

#### Evidence / Proof of Concept

Testing confirmed that the `auctioneer` account could modify auction rules through the administration interface.

![Pasted image 20261006233027.png](./evidence/Pasted%20image%2020261006233027.png)

![Pasted image 20261007105549.png](./evidence/Pasted%20image%2020261007105549.png)

![Pasted image 20261007110408.png](./evidence/Pasted%20image%2020261007110408.png)

Following rule modification and subsequent bidding activity, a reverse connection was received by the testing machine. The resulting shell executed under the **`www-data`** account; the original notes then show a transition to the local `auctioneer` account using a recovered password. Sensitive passwords and any flags are deliberately omitted here.

```text
www-data@gavel:/var/www/html/gavel/includes$ whoami
www-data
```

#### Impact

An attacker with access to the affected administration functionality could execute operating-system commands with the privileges of the web application process. This could result in disclosure or modification of files accessible to that process, alteration of application data and subsequent attempts to gain additional privileges.

#### Remediation

- Do not evaluate database-stored or user-controlled rule values as executable PHP code.
- Replace dynamic code execution with predefined rule types, validated parameters and explicitly permitted operations.
- If complex rules are required, use a restricted expression language rather than unrestricted PHP code.
- Apply least-privilege permissions to the web application account and limit access to server resources.
- Verify the fix by demonstrating that a rule can no longer invoke arbitrary PHP or operating-system operations.

---

### F04 — Privileged Code Execution Through Insecure YAML Rule Processing

| Field | Value |
| --- | --- |
| **Severity** | **High — 7.8 (provisional)** |
| **CVSS v3.1 vector** | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-94 — Improper Control of Generation of Code |
| **Related weakness** | CWE-269 — Improper Privilege Management |
| **CVE** | N/A — no applicable CVE established |
| **Affected components** | `/usr/local/bin/gavel-util`, `/opt/gavel/gaveld` |
| **Access required** | Local access able to submit auction item definitions |

#### Description

Local enumeration identified a custom utility that submits YAML-formatted auction items to a privileged backend daemon.

The YAML format contains a `rule` field interpreted as PHP code. Submitted rules are processed in a PHP environment with restrictions such as `open_basedir` and `disable_functions`.

The security weakness arises because a lower-privileged user can influence code processed by a **root-owned daemon**. If the PHP execution policy or its configuration can be bypassed, the submitted code may perform operations beyond the user's privileges.

#### Evidence / Proof of Concept

The assessment identified the root-owned `gaveld` process, the `gavel-util` submission interface and the PHP configuration used for rule evaluation:

```text
root ... /opt/gavel/gaveld
/usr/local/bin/gavel-util
/run/gaveld.sock
```

The utility advertised a `submit <file>` function for YAML item definitions. Reverse engineering in Ghidra identified rule-processing logic and a `RULE_PATH`-related configuration path.

![Pasted image 20261007123123.png](./evidence/Pasted%20image%2020261007123123.png)

![Pasted image 20261007123303.png](./evidence/Pasted%20image%2020261007123303.png)

The notes then record copying a restrictive PHP configuration into the home directory, preparing a YAML submission and invoking `gavel-util` with a user-selected configuration path. A subsequent directory listing showed a copy of root-protected content in the `auctioneer` home directory.

**Evidence limitation:** The captured sequence does not show the intermediate change or bypass needed to make a restrictive PHP configuration permit the privileged action. Before this is treated as a fully reproducible proof of root code execution, recover the relevant shell history, the effective configuration used during execution, and an unambiguous confirmation of the daemon's execution context. Do not insert unrecorded steps from a walkthrough as though they were performed during the assessment.

#### Impact

Successful exploitation of this weakness could allow a lower-privileged local user to execute code with the effective privileges of the backend daemon. Where that daemon runs as root, this may lead to unauthorised access to protected files, modification of system configuration and complete host compromise.

#### Remediation

- Avoid evaluating user-controlled PHP code inside a root-privileged service.
- Run rule validation under a dedicated unprivileged account in a strongly isolated environment with restricted filesystem and OS-level permissions.
- Prevent untrusted users from selecting, replacing or modifying security-sensitive PHP configuration files.
- Enforce a strict YAML schema accepting declarative rules rather than executable program text.
- Apply least privilege to the daemon and its communication interface.
- Retest using a non-sensitive operation that proves the effective account and demonstrates that configuration restrictions cannot be bypassed.

---

## 6. Technical Explanation — Why YAML Processing Creates a Trust-Boundary Issue

YAML is a **data format**, not executable code. A normal item definition can contain values such as:

```yaml
name: Test Item
description: A sample auction item
image: test.jpg
price: 100
rule_msg: Validating item
rule: custom_rule
```

The risk arises when the backend treats the value in a field such as `rule` as PHP source code and evaluates it. The trust boundary is:

```text
Lower-privileged user
  -> supplies YAML auction item
  -> gavel-util submits item
  -> root-owned gaveld processes it
  -> PHP rule evaluation
  -> possible privileged operation if restrictions are bypassed
```

The critical issue is **execution of untrusted code with greater privileges**, not the YAML syntax itself. In a professional report, explain the exact boundary crossed and cite the screenshot or command output proving each transition.

## 7. Conclusion

The Gavel assessment identified several weaknesses that could be chained to progressively increase attacker access.

Publicly accessible application source code assisted vulnerability discovery, SQL injection exposed account credentials, unsafe PHP rule execution provided a web-server foothold, and privileged backend rule processing created a further escalation path.

The assessment demonstrates the importance of defence in depth: secure deployment practices, safe database query construction, strong protection of privileged application functions and strict isolation of untrusted code execution.

Remediation should prioritise eliminating the code-execution paths and reducing the privileges of components processing user-controlled input, while also addressing the SQL injection and exposed repository.

## 8. References and Classification Guidance

- [Hack The Box — Gavel](https://www.hackthebox.com/machines/gavel)
- [FIRST — CVSS v3.1 Specification](https://www.first.org/cvss/v3-1/specification-document)
- [MITRE CWE-552](https://cwe.mitre.org/data/definitions/552.html)
- [MITRE CWE-89](https://cwe.mitre.org/data/definitions/89.html)
- [MITRE CWE-94](https://cwe.mitre.org/data/definitions/94.html)
- [MITRE CWE-269](https://cwe.mitre.org/data/definitions/269.html)
- [PHP — PDO Prepared Statements](https://www.php.net/manual/en/pdo.prepared-statements.php)
