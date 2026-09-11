# Key Lessons from Rejected Bug Bounty Reports

> Distilled wisdom from community experience, disclosed reports, academic research, and professional hunters.
> Every lesson here represents real time and reputation lost by hunters who learned the hard way.

---

## Lesson 1: Tool Output Is Not a Report

**The mistake:** Submitting raw output from Burp Suite, Nuclei, Nessus, Nikto, or SQLMap as a bug report.

**What happened:** Reports were immediately closed as "Not Applicable" or "Informational." Repeated submissions led to platform penalties and loss of private program access.

**The lesson:** Every professional program runs automated scanners internally. If a tool found it in 5 seconds, the program's security team already knows about it. Your value as a hunter is in manual analysis, contextual understanding, and creative exploitation -- not in running tools the program already runs.

**What to do instead:**
- Use tools for reconnaissance, not for report generation
- Manually verify every automated finding
- Write reports in your own words explaining the impact
- Include exploitation proof, not scanner output

---

## Lesson 2: Read the Scope Before You Test

**The mistake:** Spending hours or days testing assets and vulnerability types that the program explicitly excludes.

**What happened:** Valid vulnerabilities were rejected because they were on out-of-scope assets or were excluded vulnerability types. The hunter's time was completely wasted.

**The lesson:** Reading the program scope is the first thing you should do. Not the second thing. Not after you find something. The very first thing.

**What to do instead:**
- Read the entire program policy including exclusions
- Make a checklist of what is in scope and what is excluded
- Bookmark the scope page and re-check before submitting
- Check for scope updates regularly (programs change scope)

---

## Lesson 3: Impact Is Everything

**The mistake:** Reporting findings based on vulnerability type rather than demonstrated impact. "I found XSS" without showing what an attacker could actually do with it.

**What happened:** Reports were downgraded to Informational or Low because the hunter could not articulate real-world impact.

**The lesson:** A vulnerability without impact is not a vulnerability. The question is never "does this vulnerability exist?" but always "what can an attacker do with this vulnerability?"

**What to do instead:**
- Always write an "Impact" section in your report
- Describe the concrete attack scenario (who is the victim, what do they lose)
- Demonstrate the maximum impact through exploitation
- Frame the report around business impact, not technical classification

---

## Lesson 4: Quality Over Quantity

**The mistake:** Mass-submitting low-quality reports hoping some would stick. Spray-and-pray approach to bug bounty.

**What happened:** High rejection rates led to reputation damage, program bans, and leaderboard removal. On Bugcrowd, a false positive rate of 5%+ results in leaderboard removal for one month.

**The lesson:** One well-researched, clearly documented, high-impact vulnerability is worth more than twenty low-quality submissions. Your reputation is your most valuable asset in bug bounty.

**What to do instead:**
- Set a personal quality bar: would you be proud to have this report publicly disclosed?
- Spend time on report writing, not just on finding
- Self-review every report before submitting
- If you are unsure whether something is valid, research more before submitting

---

## Lesson 5: Understand the Difference Between Reconnaissance and Vulnerability Discovery

**The mistake:** Reporting reconnaissance findings as vulnerabilities. Subdomain lists, open ports, technology stacks, and directory structures submitted as reports.

**What happened:** Reports were closed as Informational. The hunter confused the beginning of their research with the end product.

**The lesson:** Reconnaissance is input to your research. Vulnerabilities are the output. Subdomains, ports, and versions are tools for you. Exploitable flaws with demonstrated impact are what you report.

**What to do instead:**
- Use reconnaissance to identify testing targets
- Only report when you find an exploitable vulnerability
- Keep your recon data private -- it is your competitive advantage

---

## Lesson 6: Duplicates Are Information, Not Failure

**The mistake:** Getting frustrated by duplicate reports and giving up, or arguing aggressively with triagers.

**What happened:** Hunters quit bug bounty entirely or damaged relationships with programs through confrontational behavior.

**The lesson:** Duplicates tell you two things: (1) your methodology is sound (you found real bugs), and (2) you need to go deeper or faster. Every top hunter has experienced duplicates. The difference is how they respond.

**What to do instead:**
- Analyze WHY you got duplicated (too slow? too shallow? same tools as everyone?)
- Adjust your approach: go deeper into the application, test newer features, develop unique methodology
- Hunt on newer programs where fewer people have looked
- Focus on business logic bugs that require deep understanding (rarely duplicated)

---

## Lesson 7: Chain Vulnerabilities Before Reporting Low-Impact Findings

**The mistake:** Reporting Self-XSS, missing headers, or low-impact issues individually.

**What happened:** Reports were rejected as "no security impact" or "best practice violation."

**The lesson:** Many individually low-impact findings become valid vulnerabilities when chained together. Self-XSS + CSRF = Stored XSS. Open redirect + OAuth = Token theft. Missing rate limiting + OTP = Authentication bypass.

**What to do instead:**
- Before reporting a low-impact finding, ask "can I chain this with something else?"
- Spend time looking for the second link in the chain
- Report the chain as a single finding with the combined impact
- If you cannot find a chain, the finding is likely not worth reporting

---

## Lesson 8: Context Matters More Than Vulnerability Type

**The mistake:** Assuming all instances of a vulnerability type have the same severity. "SQLi is always Critical." "XSS is always High."

**What happened:** Severity was disputed and downgraded because the context did not support the claimed severity.

**The lesson:** The same vulnerability type can range from Informational to Critical depending on:
- What data is accessible
- What actions can be performed
- What authentication is required
- What compensating controls exist
- What the business impact is

**What to do instead:**
- Evaluate severity based on demonstrated impact, not vulnerability classification
- Be honest about limitations in your report
- Describe what you CAN do, not what the vulnerability type COULD theoretically allow
- Proactively mention any restrictions or conditions

---

## Lesson 9: Persistence Beats Talent

**The mistake:** Giving up after a few rejections or comparing yourself to top researchers.

**What happened:** Many talented individuals left bug bounty after initial failures, missing the learning curve that leads to success.

**The lesson:** Every successful bug bounty hunter has a history of rejections, duplicates, and informational reports. The ones who succeed are the ones who learn from each rejection and keep going. Rejection teaches more than labs ever will.

**What to do instead:**
- Treat each rejection as a learning opportunity
- Keep a log of what was rejected and why
- Study disclosed reports to understand what gets accepted
- Set realistic expectations: your first months will have more rejections than acceptances

---

## Lesson 10: Communicate Professionally

**The mistake:** Arguing with triagers, being rude in comments, publicly shaming programs for rejections, or threatening disclosure.

**What happened:** Permanent bans from programs and platforms. Loss of private program invitations. Reputation damage in the community.

**The lesson:** Bug bounty is a professional relationship. Triagers and security teams are people with their own constraints and perspectives. Professional communication gets better outcomes than confrontation.

**What to do instead:**
- Be respectful in all communications
- If you disagree, provide evidence calmly
- Use platform mediation for disputes
- Never publicly disclose before authorization
- Build relationships with security teams through quality work

---

## Lesson 11: Do Not Report What You Cannot Explain

**The mistake:** Submitting a finding because a tool flagged it, without understanding what the vulnerability actually is or why it matters.

**What happened:** When triagers asked clarifying questions, the hunter could not explain the impact or reproduce the issue. Report closed as invalid.

**The lesson:** If you cannot explain the vulnerability in plain language, you do not understand it well enough to report it. Understanding is a prerequisite for reporting.

**What to do instead:**
- Research the vulnerability type before reporting
- Be able to explain: what is the flaw, how does it work, what can an attacker do, and how to fix it
- If you are unsure, study more before submitting
- Test your explanation by writing it out -- if it does not make sense to you, it will not make sense to the triager

---

## Lesson 12: Programs Have Context You Do Not

**The mistake:** Insisting that a finding is Critical when the program rates it Medium or Low.

**What happened:** Lengthy, unproductive disputes that wasted everyone's time.

**The lesson:** Programs know things you do not: internal network segmentation, compensating controls, data sensitivity classifications, business context, and risk appetite. Their severity assessment may incorporate factors you cannot see from the outside.

**What to do instead:**
- Present your evidence clearly and let the program make the final call
- Ask for the reasoning behind downgrades (you will learn something)
- Accept that your outside perspective has inherent limitations
- Use the experience to calibrate your severity assessments for future reports

---

## Summary: The Anti-Pattern Checklist

Before submitting any report, verify you are NOT doing any of these:

- [ ] Submitting raw tool output
- [ ] Reporting on out-of-scope assets
- [ ] Reporting a vulnerability type the program excludes
- [ ] Reporting without a proof of concept
- [ ] Reporting without demonstrated impact
- [ ] Reporting reconnaissance findings as vulnerabilities
- [ ] Reporting best practice violations as vulnerabilities
- [ ] Overestimating severity based on vulnerability type alone
- [ ] Submitting Self-XSS without a delivery chain
- [ ] Reporting something you cannot explain in plain language
- [ ] Mass-submitting low-quality reports
- [ ] Reporting known/accepted risk the program has already acknowledged

---

## The Golden Rule of Bug Bounty Reporting

**If you cannot describe a realistic attack scenario where a real attacker harms a real user or the organization, do not submit the report.**

Everything flows from this principle. Impact drives severity. Exploitation proves the finding. Context determines relevance. Without these, you have reconnaissance notes, not a vulnerability report.
