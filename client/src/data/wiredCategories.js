// Which tool sections have their Config, Scan and Results wired up to the server.
//
// Its own module so App.js and the test that guards it read the SAME list. A test holding a second
// copy would have passed while the app stayed broken, which is exactly how the redirect-ssrf section
// shipped with unwired cards: the key here said 'redirect' and the section said 'redirect-ssrf'.
//
// Every entry MUST match a section key in attackTools.js AND a category the server registers.
export const WIRED_CATEGORIES = ['xss', 'sqli', 'cmdi', 'redirect-ssrf', 'lfi', 'cache', 'smuggling', 'access-bypass', 'graphql', 'sensitive-leak', 'exposed-git', 'misc'];

export default WIRED_CATEGORIES;
