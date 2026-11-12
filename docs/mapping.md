# Control mapping sources and decisions

Pinned benchmark: **CIS Amazon Web Services Foundations Benchmark v7.1.0** (dated 10-02-2026).
Other sources: NIST SP 800-53 Rev 5 catalog; ISO/IEC 27001:2022 Annex A; AICPA SOC 2 Trust Services Criteria.
CIS recommendation numbers change between benchmark versions, so every CIS number below is for v7.1.0 only.
Cite recommendations by number. Do not copy benchmark text into this repo (see CIS terms of use).

The NIST, ISO and SOC 2 columns are a judgment, not an official crosswalk. Each row says why the mapping holds,
and where the scanner covers less (or more) than the CIS recommendation, the notes say so.

Scope notes that apply to several checks:

- **Regions.** IAM is global. S3 bucket lists are account-wide. Config, VPC, security group, KMS and CloudTrail
  trail lists are read for one region per run (`--region`), and every evidence record carries its region.
  Run once per region to cover an account.
- **No data must not pass.** If AWS cannot answer, or a needed value is missing, the result is ERROR or FAIL,
  never PASS.
- **One record per resource** (user, bucket, trail, security group, VPC, key), so each is its own evidence.

| Check | CIS v7.1.0 | CIS status | NIST 800-53 r5 | ISO 27001:2022 | SOC 2 | Why this mapping / notes |
|-------|-----------|------------|----------------|----------------|-------|--------------------------|
| IAM-01 root MFA | 2.5 | Automated | IA-2(1) | A.8.5 | CC6.1 | The root user can do anything, so a second sign-in factor means a stolen password alone cannot take over the account. Checks that MFA is on, not that the device is a hardware key (CIS 2.6, Manual). |
| IAM-02 root access keys | 2.4 | Automated | AC-6(5) | A.8.2 | CC6.1 | Root access keys are a permanent, unrestricted credential for programs. Having none keeps root access to deliberate, interactive use. Missing data raises an error rather than passing. |
| IAM-03 console users have MFA | 2.10 | Automated | IA-2(1) | A.8.5 | CC6.1 | A user who can sign in with a password but has no second factor is exposed to password theft. Users with no console password are not judged, because they cannot sign in to the console. |
| IAM-04 unused credentials (45 days) | 2.11 | Automated | AC-2(3) | A.5.18 | CC6.2 | An active credential nobody uses is an unwatched way in. Only active passwords and keys count. A credential never used is measured from its creation date. The rule is 45 days or more. |
| IAM-05 key rotation (90 days) | 2.12 | Automated | IA-5 | A.5.17 | CC6.1 | The older an access key is, the more places it may have been copied, so regular replacement limits how long a leak stays useful. Only active keys count. The rule is more than 90 days (exactly 90 passes). |
| IAM-06 no full-admin wildcard policy | 2.14 | Automated | AC-6 | A.8.2 | CC6.3 | A policy that allows every action on every resource ignores least privilege. Only attached customer and AWS managed policies are judged. Inline policies are not covered (and CIS 2.14 does not audit them). A Deny statement is not admin. |
| S3-07 public access block | 3.1.4 | Automated | AC-3 | A.8.3 | CC6.1 | The four Block Public Access settings are a guard that keeps buckets from being opened to the internet by mistake. Checked at account level and for every bucket. A missing setting counts as off. Strict: a bucket with no setting of its own fails even if the account level protects it. |
| S3-08 default encryption | 3.1.5 | Manual | SC-28 | A.8.24 | CC6.1 | Default encryption means objects are stored encrypted without relying on each uploader to ask for it. CIS lists this as Manual; the scanner automates the "is encryption on" part only and does not judge the key management. |
| S3-09 versioning | none | n/a | CP-9 | A.8.13 | A1.2 | Versioning keeps earlier copies of objects, so an accidental delete or overwrite can be undone. Not its own CIS recommendation in v7.1.0: versioning appears only inside 3.1.2 (MFA Delete). Only the status Enabled passes; Suspended and never-enabled fail. |
| S3-10 server access logging | 4.4 (partial) | Manual | AU-12 | A.8.15 | CC7.2 | Server access logs give an audit trail of who requested which objects. CIS 4.4 covers the CloudTrail S3 bucket only; this check covers every bucket, which is broader. A bucket that only receives logs also fails unless it logs elsewhere. |
| CT-11 multi-region trail logging | 4.1 | Manual | AU-12 | A.8.15 | CC7.2 | A trail that records management events in every region is the account's activity history. Needs at least one trail that is multi-region, logging, and recording all management events (reads and writes). CIS lists this as Manual; the scanner automates it. No trail at all is a FAIL. |
| CT-12 log file validation | 4.2 | Automated | AU-9 | A.8.15 | CC7.2 | Log file validation signs a fingerprint of each log file, so tampering or deletion can be detected. This protects the integrity of the audit record. No trail at all is a FAIL. |
| CT-13 trail logs encrypted with KMS | 4.5 | Automated | SC-28 | A.8.24 | CC6.1 | Encrypting trail logs with a KMS key means reading them also needs permission on the key, not only on the bucket. The trail passes when a KMS key is set. No trail at all is a FAIL. |
| CFG-14 Config recorder on | 4.3 | Automated | CM-8 | A.8.9 | CC7.1 | AWS Config keeps a history of how resources were configured, which supports an inventory and change tracking. Passes when the recorder records all supported resource types and is running. Limits: judges one region per run; records `lastStatus` as evidence but does not require SUCCESS; does not judge the global-resources setting, which CIS needs in only one region. |
| VPC-15 flow logs | 4.7 | Automated | SI-4 | A.8.16 | CC7.2 | Flow logs record which network connections reached a VPC and which were refused, which supports spotting unusual traffic. Requires an ACTIVE flow log with traffic type REJECT or ALL, because the CIS description recommends recording rejected packets (stricter than the audit step, which asks only for an active log). |
| VPC-16 default security group | 6.5 | Automated | SC-7 | A.8.20 | CC6.6 | A default security group with no rules means anything launched into it by accident cannot communicate, which pushes people to write deliberate least-privilege rules. Passes only with zero inbound and zero outbound rules. A new AWS account fails this by default. |
| VPC-17 SSH open to 0.0.0.0/0 | 6.3 | Automated | SC-7 | A.8.20 | CC6.6 | Opening the SSH port to the whole internet invites password guessing against servers, so limiting sources is boundary protection. 6.3 covers SSH and RDP together; IPv6 (::/0) is CIS 6.4 and is not covered yet. |
| VPC-18 RDP open to 0.0.0.0/0 | 6.3 | Automated | SC-7 | A.8.20 | CC6.6 | Same reasoning as VPC-17 for port 3389. Port ranges (such as 0-3389) and protocol -1 (all traffic) include the port, so they fail too. |
| KMS-19 key rotation | 4.6 | Automated | SC-12 | A.8.24 | CC6.1 | Rotating a key limits how much data a leaked key can unlock, which supports key management. Judged only on enabled, symmetric, customer-managed keys with AWS-created key material, because the others cannot (or do not need to) rotate. No such keys is a PASS. |
| IAM-20 password policy | 2.8 and 2.9 | Automated | IA-5(1) | A.5.17 | CC6.1 | Long passwords and no reuse make guessing and recycling attacks harder, which is the password-strength requirement. Needs a minimum length of 14 or more (2.8) and reuse prevention of 24 (2.9, CIS example value, also the AWS maximum). No custom policy is a FAIL. |
