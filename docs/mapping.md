# Control mapping sources and decisions

Pinned benchmark: **CIS Amazon Web Services Foundations Benchmark v7.1.0** (dated 10-02-2026).
Other sources: NIST SP 800-53 Rev 5 catalog; ISO/IEC 27001:2022 Annex A; AICPA SOC 2 Trust Services Criteria.
CIS recommendation numbers change between benchmark versions, so every CIS number below is for v7.1.0 only.
Cite recommendations by number. Do not copy benchmark text into this repo (see CIS terms of use).

The NIST, ISO and SOC 2 columns are a starting judgment, not an official crosswalk. Check each against its
source and write the reason in your own words.

| Check | CIS v7.1.0 | CIS status | NIST 800-53 r5 | ISO 27001:2022 | SOC 2 | Why this mapping / notes |
|-------|-----------|------------|----------------|----------------|-------|--------------------------|
| IAM-01 root MFA | 2.5 | Automated | IA-2(1) | A.8.5 | CC6.1 | TODO |
| IAM-02 root access keys | 2.4 | Automated | AC-6(5) | A.8.2 | CC6.1 | TODO |
| IAM-03 console users have MFA | 2.10 | Automated | IA-2(1) | A.8.5 | CC6.1 | TODO |
| IAM-04 unused credentials (45 days) | 2.11 | Automated | AC-2(3) | A.5.18 | CC6.2 | TODO |
| IAM-05 key rotation (90 days) | 2.12 | Automated | IA-5 | A.5.17 | CC6.1 | TODO |
| IAM-06 no full-admin wildcard policy | 2.14 | Automated | AC-6 | A.8.2 | CC6.3 | TODO |
| S3-07 public access block | 3.1.4 | Automated | AC-3 | A.8.3 | CC6.1 | TODO |
| S3-08 default encryption | 3.1.5 | Manual | SC-28 | A.8.24 | CC6.1 | CIS lists this as Manual; the scanner automates the "is encryption on" part only |
| S3-09 versioning | none | n/a | CP-9 | A.8.13 | A1.2 | Not its own CIS recommendation in v7.1.0. Versioning appears only inside 3.1.2 (MFA Delete). Say so. |
| S3-10 server access logging | 4.4 (partial) | Manual | AU-12 | A.8.15 | CC7.2 | CIS 4.4 covers the CloudTrail S3 bucket only; this check covers every bucket, which is broader |
| CT-11 multi-region trail logging | 4.1 | Manual | AU-12 | A.8.15 | CC7.2 | CIS lists this as Manual; the scanner automates it |
| CT-12 log file validation | 4.2 | Automated | AU-9 | A.8.15 | CC7.2 | TODO |
| CT-13 trail logs encrypted with KMS | 4.5 | Automated | SC-28 | A.8.24 | CC6.1 | TODO |
| CFG-14 Config recorder on | 4.3 | Automated | CM-8 | A.8.9 | CC7.1 | TODO |
| VPC-15 flow logs | 4.7 | Automated | SI-4 | A.8.16 | CC7.2 | TODO |
| VPC-16 default security group | 6.5 | Automated | SC-7 | A.8.20 | CC6.6 | TODO |
| VPC-17 SSH open to 0.0.0.0/0 | 6.3 | Automated | SC-7 | A.8.20 | CC6.6 | 6.3 covers SSH and RDP together; also consider 6.4 for IPv6 (::/0) |
| VPC-18 RDP open to 0.0.0.0/0 | 6.3 | Automated | SC-7 | A.8.20 | CC6.6 | Same CIS recommendation as VPC-17. Port ranges and protocol -1 can also include the port |
| KMS-19 key rotation | 4.6 | Automated | SC-12 | A.8.24 | CC6.1 | TODO |
| IAM-20 password policy | 2.8 and 2.9 | Automated | IA-5(1) | A.5.17 | CC6.1 | Length of 14 or more (2.8) and reuse prevention (2.9, CIS example value is 24 or more) |
