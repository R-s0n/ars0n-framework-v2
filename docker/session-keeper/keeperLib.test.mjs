// Unit tests for the keeper's pure helpers. Run: node keeperLib.test.mjs
// The egress match is scope-safety-critical, so it is tested hardest: a bug here sends the operator's
// session somewhere it should not go.

import assert from 'assert';
import { hostMatches, hostOf, toPuppeteerCookie, accessTokenFromBody, stripBearer } from './keeperLib.mjs';

let pass = 0;
const ok = (label, cond) => { assert.ok(cond, label); pass++; };

// --- egress allowlist match ---
const allow = ['app.staging-v2.tradetalk.us', 'tradetalk.us', 'cognito-idp.us-east-1.amazonaws.com'];
ok('exact in-scope host allowed', hostMatches('app.staging-v2.tradetalk.us', allow));
ok('subdomain of an allowed suffix allowed', hostMatches('x.tradetalk.us', allow));
ok('exact auth host allowed', hostMatches('cognito-idp.us-east-1.amazonaws.com', allow));
ok('unrelated host REFUSED', !hostMatches('evil.example.com', allow));
ok('label-boundary: nottradetalk.us is NOT inside tradetalk.us', !hostMatches('nottradetalk.us', allow));
ok('a lookalike suffix is refused', !hostMatches('tradetalk.us.evil.com', allow));
ok('empty allowlist refuses everything (fail closed)', !hostMatches('app.staging-v2.tradetalk.us', []));
ok('empty host refused', !hostMatches('', allow));
ok('case-insensitive match', hostMatches('APP.Staging-v2.TradeTalk.us', allow));

// --- hostOf ---
ok('hostOf parses a url', hostOf('https://app.example.com/x?y=1') === 'app.example.com');
ok('hostOf on junk is empty', hostOf('not a url') === '');

// --- stripBearer ---
ok('stripBearer pulls the token', stripBearer('Bearer abc.def.ghi') === 'abc.def.ghi');
ok('stripBearer is case-insensitive', stripBearer('bearer xyz') === 'xyz');
ok('stripBearer ignores a non-bearer', stripBearer('Basic abc') === '');
ok('stripBearer on empty is empty', stripBearer('') === '');

// --- accessTokenFromBody ---
ok('accessTokenFromBody reads a token response', accessTokenFromBody('{"access_token":"T","expires_in":900}') === 'T');
ok('accessTokenFromBody on a non-token body is empty', accessTokenFromBody('{"foo":"bar"}') === '');
ok('accessTokenFromBody on non-json is empty', accessTokenFromBody('<html>') === '');

// --- toPuppeteerCookie ---
const c1 = toPuppeteerCookie({ name: 'sid', value: 'v', domain: '.example.com', path: '/', secure: true, httpOnly: true, sameSite: 'None' }, 'https://app.example.com');
ok('cookie keeps name/value/path', c1.name === 'sid' && c1.value === 'v' && c1.path === '/');
ok('leading dot stripped from domain', c1.domain === 'example.com');
ok('secure + httpOnly carried', c1.secure === true && c1.httpOnly === true);
ok('sameSite normalised to Chromium casing', c1.sameSite === 'None');
const c2 = toPuppeteerCookie({ name: 'a', value: 'b', sameSite: 'weird' }, 'https://app.example.com');
ok('domainless cookie gets a url fallback', c2.url === 'https://app.example.com' && c2.domain === undefined);
ok('unrecognised sameSite omitted', c2.sameSite === undefined);

console.log(`${pass} passed, 0 failed`);
