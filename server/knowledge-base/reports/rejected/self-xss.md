# Self-XSS and Similar Non-Exploitable Findings

> Detailed guide on Self-XSS and other vulnerability classes that appear exploitable but lack a viable attack vector.

---

## What Is Self-XSS?

Self-XSS is a form of Cross-Site Scripting where the injected JavaScript only executes in the attacker's own browser session. There is no way to deliver the payload to a victim -- the user would have to inject the payload into their own session manually.

Self-XSS is the single most commonly rejected "vulnerability" in bug bounty programs. Almost every program explicitly excludes it.

---

## Why Self-XSS Is Not a Vulnerability

For XSS to be a real vulnerability, it must satisfy the "victim interaction" requirement:

1. **Reflected XSS:** Attacker crafts a URL containing the payload; victim clicks the URL
2. **Stored XSS:** Attacker stores the payload; victim views the page containing it
3. **DOM-based XSS:** Attacker crafts input that triggers client-side JavaScript to execute the payload

**Self-XSS fails this test** because:
- The payload only appears in the user's own session
- No URL, link, or external trigger can deliver the payload to another user
- The victim would have to paste malicious code into their own browser

---

## Common Self-XSS Scenarios

### 1. XSS in User Profile Fields (Visible Only to Self)

**What was submitted:** XSS in a profile bio, display name, or settings field that only renders on the user's own dashboard.

**Why it was rejected:** The payload is only visible to the user who entered it. No other user sees the rendered output.

**What the hunter should have done differently:**
- Check if the field is rendered to other users (e.g., on a public profile, in comments, in shared views)
- If it only renders on the user's own dashboard, it is Self-XSS
- Test if the field appears in admin panels (stored XSS for admin)

**Key lesson:** Always verify WHO sees the rendered output. If only the inputting user sees it, it is Self-XSS.

---

### 2. XSS in Search Results (Own Query Only)

**What was submitted:** Injecting XSS into a search query that reflects in the search results page.

**Why it was rejected:** If the search query is only in the request body (POST) and not in the URL, there is no way to send a victim a link containing the payload. This makes it Self-XSS.

**What the hunter should have done differently:**
- Verify if the search uses GET parameters (URL-based, linkable)
- If GET-based, it is Reflected XSS (valid)
- If POST-based with no URL reflection, it is Self-XSS (invalid)
- Check if the search term is stored and shown to other users (e.g., "popular searches")

**Key lesson:** POST-based XSS without URL reflection is usually Self-XSS. GET-based XSS with URL parameters is Reflected XSS.

---

### 3. XSS via Browser Developer Console

**What was submitted:** Executing JavaScript by pasting code into the browser's developer console.

**Why it was rejected:** This is not a vulnerability at all. Users can always execute JavaScript in their own browser console. This is by design.

**What the hunter should have done differently:**
- Never report console-based execution as XSS
- Understand that the browser console is a developer tool, not an attack vector
- Focus on injection points within the application itself

**Key lesson:** Browser console execution is never a vulnerability. It is a tool feature.

---

### 4. XSS in File Upload Names (Own View Only)

**What was submitted:** Uploading a file with a malicious filename (e.g., `<script>alert(1)</script>.jpg`) that triggers XSS when viewing your own uploads.

**Why it was rejected:** The filename only renders in the uploader's own file listing. No other user sees the raw filename.

**What the hunter should have done differently:**
- Check if the filename renders to other users (shared files, admin panels, public galleries)
- Check if the filename appears in email notifications to admins
- If only visible to the uploader, it is Self-XSS

**Key lesson:** File upload XSS is only valid if the filename renders to other users or administrators.

---

### 5. XSS in Draft/Unpublished Content

**What was submitted:** XSS in a blog draft, unpublished comment, or pending content that has not been published.

**Why it was rejected:** Unpublished content is only visible to the author. Until it is published and visible to others, XSS in drafts is Self-XSS.

**What the hunter should have done differently:**
- Check if draft content is visible to editors, moderators, or admins
- If content goes through a review workflow, check if the XSS triggers for the reviewer
- Only report if the payload reaches another user

---

## When Self-XSS CAN Become a Valid Vulnerability

Self-XSS can be escalated to a valid vulnerability when chained with another bug:

### Self-XSS + CSRF = Stored XSS

If you find:
1. Self-XSS in a profile field (user can inject XSS visible only to themselves)
2. CSRF vulnerability on the profile update endpoint (attacker can force a victim to update their profile)

**Combined attack:** Attacker uses CSRF to inject the XSS payload into the victim's profile, making it execute in the victim's session.

**This IS reportable** because the attacker can deliver the payload to the victim without the victim's knowledge.

### Self-XSS + Login CSRF = Account Fixation + XSS

If you find:
1. Self-XSS in a dashboard field
2. Login CSRF (can force victim to log into attacker's account)

**Combined attack:** Attacker forces victim to log into attacker's account (with XSS payload pre-loaded), executes JavaScript in the victim's browser.

### Self-XSS + Clickjacking = Forced Input

If you find:
1. Self-XSS in a form field
2. The page with the form can be iframed (no X-Frame-Options)

**Combined attack:** Attacker creates a page that iframes the vulnerable form and tricks the victim into typing the payload.

---

## Other Non-Exploitable Finding Categories

### Content Spoofing Without Security Impact

**What was submitted:** Ability to inject HTML content (without JavaScript) into a page.

**Why it was rejected:** HTML injection without script execution is cosmetic. It cannot steal credentials, cookies, or perform actions on behalf of the user.

**When it IS valid:** HTML injection on a login page that can create a convincing fake login form (phishing via content injection).

---

### Tabnabbing / Reverse Tabnabbing

**What was submitted:** Links with `target="_blank"` without `rel="noopener noreferrer"`.

**Why it was rejected:** Modern browsers (since ~2021) automatically apply `noopener` behavior to `target="_blank"` links. This vulnerability class is effectively dead in modern browsers.

**Key lesson:** Tabnabbing via `target="_blank"` is a historical vulnerability. Modern browsers mitigate it automatically.

---

### Text Injection in Emails

**What was submitted:** Ability to inject text into application-generated emails by manipulating form fields.

**Why it was rejected:** Unless you can modify email headers (FROM, TO, CC, BCC) or inject HTML that creates phishing content, text in the email body is typically not exploitable.

---

### Password Reset Token in URL (Referrer Leak)

**What was submitted:** Password reset links contain the token in the URL, which could leak via the Referer header.

**Why it was rejected:** Modern applications set `Referrer-Policy` headers, and password reset pages typically have no external links. The token in the URL is standard practice.

**When it IS valid:** If the password reset page loads external resources (analytics, fonts, etc.) that could capture the Referer header containing the token.

---

## Self-XSS Decision Flowchart

```
You found XSS in a field/parameter. Ask:
  |
  +-- Can you send a URL to a victim that triggers the XSS?
  |     YES --> Reflected XSS (VALID - report it)
  |     NO  --> Continue...
  |
  +-- Does the stored payload render to OTHER users?
  |     YES --> Stored XSS (VALID - report it)
  |     NO  --> Continue...
  |
  +-- Can you chain with CSRF to inject the payload into a victim's session?
  |     YES --> Self-XSS + CSRF chain (VALID - report the chain)
  |     NO  --> Continue...
  |
  +-- Can you chain with any other delivery mechanism?
        YES --> Document the chain and report
        NO  --> SELF-XSS (INVALID - do not report)
```

---

## Key Rules for XSS Reporting

1. **Always verify the delivery mechanism** - How does the payload reach the victim?
2. **Always verify the rendering context** - Who sees the rendered output?
3. **POST-based reflection without URL parameters = usually Self-XSS**
4. **Own-session-only rendering = always Self-XSS**
5. **Browser console execution = never a vulnerability**
6. **Chain Self-XSS with other bugs before reporting**
7. **If you cannot describe the attack scenario with a victim, do not report**
