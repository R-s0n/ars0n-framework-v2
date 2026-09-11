# Common Reasons Bug Bounty Reports Get Rejected

> Reference guide for understanding why reports are rejected and how to avoid wasting time and reputation.
> Based on analysis of HackerOne disclosed reports, Bugcrowd taxonomy, academic research (arxiv:2511.18608), and community knowledge.

---

## 1. Previously Known / Already Reported Vulnerability

**What was submitted:** A valid vulnerability that another researcher already reported.

**Why it was rejected:** The vulnerability was already in the program's backlog or had been reported by another hunter. This is the single largest category of rejected reports across all platforms.

**What the hunter should have done differently:**
- Check publicly disclosed reports on HackerOne/Bugcrowd for similar findings
- Focus on deeper, less obvious vulnerabilities rather than low-hanging fruit
- Hunt on newer programs or recently updated assets where fewer researchers have looked
- Develop unique methodology rather than running the same tools as everyone else

**Key lesson:** If an automated tool found it in 5 seconds, it has almost certainly been reported already. Every professional program is already running automated scanners internally.

---

## 2. False Positive / Not Actually Vulnerable

**What was submitted:** A scanner output or tool finding that appeared to show a vulnerability but was not actually exploitable.

**Why it was rejected:** The hunter submitted raw tool output without manual verification. The "vulnerability" was a false positive from automated scanning.

**What the hunter should have done differently:**
- Manually verify every finding before submission
- Actually exploit the vulnerability to confirm it works
- Never submit raw Burp Suite, Nuclei, or Nessus output as a report
- Understand the difference between a theoretical vulnerability and an exploitable one

**Key lesson:** "My automation tool says the payload was successful" is never sufficient evidence. Always manually confirm exploitability.

---

## 3. Out of Scope

**What was submitted:** A vulnerability on an asset, domain, or vulnerability class that the program explicitly excludes.

**Why it was rejected:** The hunter did not read (or did not fully understand) the program's scope and rules.

**What the hunter should have done differently:**
- Read the entire program policy before testing
- Pay special attention to the "Out of Scope" section
- Check which domains, subdomains, and IP ranges are in scope
- Verify which vulnerability types are accepted

**Key lesson:** Always read the program scope completely. A valid vulnerability on an out-of-scope asset is still a rejection.

---

## 4. Insufficient Proof / No PoC

**What was submitted:** A report claiming a vulnerability exists but providing no proof of concept, unclear reproduction steps, or inadequate evidence.

**Why it was rejected:** The security team could not reproduce the issue or verify the claim. Placeholder submissions with vague titles and few details are immediately rejected.

**What the hunter should have done differently:**
- Provide clear, numbered steps to reproduce
- Include screenshots, videos, or HTTP request/response pairs
- Show the actual security impact with a working exploit
- Test reproduction steps on a clean browser/environment before submitting

**Key lesson:** A poorly documented valid vulnerability gets rejected just as fast as a non-vulnerability. Report quality matters as much as the finding itself.

---

## 5. No Security Impact / Informational Only

**What was submitted:** A finding that is technically accurate but poses no real security risk to users or the organization.

**Why it was rejected:** The issue has no exploitable security impact. It may be a best practice violation or cosmetic issue rather than a security vulnerability.

**What the hunter should have done differently:**
- Ask "So what?" - what can an attacker actually do with this?
- Consider if the finding affects confidentiality, integrity, or availability
- If the impact is purely theoretical, it is likely not worth reporting
- Focus on findings where you can demonstrate real-world harm

**Key lesson:** A vulnerability without impact is not a vulnerability. Always articulate the concrete attack scenario.

---

## 6. Best Practice Violation (Not a Vulnerability)

**What was submitted:** Missing security headers, missing DMARC/SPF/DKIM records, missing rate limiting on non-sensitive endpoints, cookie flags, or similar best-practice issues.

**Why it was rejected:** These are configuration recommendations, not exploitable vulnerabilities. Programs call these "beg bounties" - findings where the hunter begs for a reward for something that is not a security issue.

**What the hunter should have done differently:**
- Understand the difference between a security recommendation and a vulnerability
- Only report missing controls when they lead to a demonstrable exploit
- Chain the missing control with another vulnerability if possible

**Key lesson:** Missing a best practice does not equal a vulnerability. If you cannot demonstrate an exploit, do not submit.

---

## 7. Spam / Low-Quality / AI-Generated Reports

**What was submitted:** Reports generated by AI tools, mass-produced scanner outputs, or vague reports with no real analysis.

**Why it was rejected:** The report shows no evidence of actual security testing or understanding of the vulnerability. Programs have zero tolerance for spam submissions.

**What the hunter should have done differently:**
- Write reports personally with specific details about the target
- Demonstrate understanding of why the vulnerability matters in context
- Show evidence of manual testing beyond automated scanning

**Key lesson:** AI-generated and mass-produced reports damage your reputation permanently. Platforms like HackerOne and Immunefi penalize accounts with high false-positive rates.

---

## 8. Requires Unlikely User Interaction

**What was submitted:** A vulnerability that requires the victim to perform an unrealistic series of actions, such as pasting code into their browser console, installing a malicious extension, or clicking through multiple warnings.

**Why it was rejected:** The attack scenario is not realistic. No reasonable user would perform the required actions.

**What the hunter should have done differently:**
- Evaluate the attack scenario from the victim's perspective
- Consider whether a real attacker could realistically exploit this
- Self-XSS is the most common example - only you can trigger it on yourself

**Key lesson:** If the attack requires the victim to essentially hack themselves, it is not a vulnerability.

---

## 9. Known/Accepted Risk

**What was submitted:** A vulnerability or configuration that the organization is already aware of and has accepted the risk for.

**Why it was rejected:** The organization made a deliberate business decision to accept this risk. Common examples include allowing certain information disclosure for usability reasons.

**What the hunter should have done differently:**
- Check if the behavior appears intentional
- Look for explicit documentation about accepted risks
- Focus testing on areas where the organization is clearly trying to enforce security

**Key lesson:** Not every security imperfection is a bug. Organizations make deliberate risk acceptance decisions.

---

## 10. Publicly Disclosed Before Fix

**What was submitted:** A valid vulnerability, but the hunter disclosed it publicly (blog, social media, GitHub) before the program had time to fix it.

**Why it was rejected:** This violates responsible disclosure policies and the program's terms. Even valid, critical vulnerabilities get rejected (and the hunter potentially banned) for premature disclosure.

**What the hunter should have done differently:**
- Never disclose publicly until the program authorizes it
- Follow the platform's disclosure timeline (typically 90 days)
- Request mutual disclosure through the platform's process

**Key lesson:** Premature disclosure turns a valid finding into a policy violation. Patience is required.

---

## Rejection Rate Statistics

Based on academic research analyzing 9,942 disclosed HackerOne reports:
- **8,542 (86%)** were accepted as valid
- **1,400 (14%)** were not accepted
- The most common invalid reasons in order: previously known, false positive, out of scope, duplicate, no PoC

Note: These statistics only reflect *disclosed* reports. The actual rejection rate across all submissions (including non-disclosed) is significantly higher.

---

## Impact on Hunter Reputation

- **HackerOne Signal:** Invalid reports decrease your Signal score, affecting program invitations
- **Bugcrowd:** A false positive rate of 5% or higher results in leaderboard removal for one month
- **Immunefi:** Zero tolerance for beg bounty behavior, spam, or misrepresentation of severity
- **General:** Consistent low-quality submissions lead to platform bans and loss of private program access

---

## Decision Framework: Should I Submit This Report?

Before submitting, answer YES to ALL of these:

1. Is the asset in scope?
2. Is this vulnerability type accepted by the program?
3. Have I manually verified exploitability?
4. Can I demonstrate real security impact?
5. Do I have clear reproduction steps and evidence?
6. Have I checked for existing public disclosures of this issue?
7. Would a senior security engineer consider this a real threat?

If any answer is NO, do not submit.
