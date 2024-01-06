# CVE Tools

- [CVE Tools](#cve-tools)
  - [Purpose](#purpose)
  - [ITS CVE - 2023 - 32233 Detection Script](#its-cve---2023---32233-detection-script)
    - [The CVE](#the-cve)
      - [CVE-ID](#cve-id)
      - [Description](#description)
      - [References](#references)
      - [Assigning CNA](#assigning-cna)
      - [Date Record Created](#date-record-created)
      - [Phase (Legacy)](#phase-legacy)
  - [detect-spry.sh](#detect-sprysh)
    - [Created By:](#created-by)
    - [Version:](#version)

## Purpose

These are a collection of scripts that I wrote to help the Linux Admin team with certain CVEs.

## ITS CVE - 2023 - 32233 Detection Script

This script will detect the afflicted Kernel and module

### The CVE

#### CVE-ID

CVE-2023-32233

#### Description

In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users can obtain root privileges. This occurs because anonymous sets are mishandled.

#### References

Note: References are provided for the convenience of the reader to help distinguish between vulnerabilities. The list is not intended to be complete.

- MISC:https://bugzilla.redhat.com/show_bug.cgi?id=2196105
- MISC:https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=c1592a89942e9678f7d9c8030efa777c0d57edab
- MISC:https://github.com/torvalds/linux/commit/c1592a89942e9678f7d9c8030efa777c0d57edab
- MISC:https://news.ycombinator.com/item?id=35879660
- MISC:https://www.openwall.com/lists/oss-security/2023/05/08/4

#### Assigning CNA

MITRE Corporation

#### Date Record Created

20230505	Disclaimer: The record creation date may reflect when the CVE ID was allocated or reserved, and does not necessarily indicate when this vulnerability was discovered, shared with the affected vendor, publicly disclosed, or updated in CVE.

#### Phase (Legacy)

Assigned (20230505)

---

## detect-spry.sh

This script will detect to see if the malware SprySOCS is running and will attempt to kill it

### Created By: 

Christopher Tarricone chris at uconn dot edu

### Version:

1.0 - Initial Creation
2.0 - Added IOC for libmonitor.so.2