// Unit tests for the keeper's pure helpers. Run: node keeperLib.test.mjs
// The egress match is scope-safety-critical, so it is tested hardest: a bug here sends the operator's
// session somewhere it should not go.

import assert from 'assert';
import { hostMatches, hostOf, toPuppeteerCookie, accessTokenFromBody, stripBearer, validateLoginConfig, buildLoginPlan, loginUrlAllowed } from './keeperLib.mjs';

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

// --- login config validation (the sequence interpreter, no network) ---
const goodLogin = {
  login_url: 'https://app.staging-v2.tradetalk.us/login',
  steps: [
    { selector: '#username', action: 'type', value_ref: 'username' },
    { selector: '#password', action: 'type', value_ref: 'password' },
    { selector: '#remember', action: 'click' },
    { selector: 'button[type=submit]', action: 'submit' },
  ],
  success: { kind: 'bearer' },
  username: 'u', password: 'p',
};
ok('a complete login config validates', validateLoginConfig(goodLogin).ok);
ok('a login config with no url is rejected', !validateLoginConfig({ ...goodLogin, login_url: '' }).ok);
ok('a login config with no steps is rejected', !validateLoginConfig({ ...goodLogin, steps: [] }).ok);
ok('a type step with no value_ref is rejected',
  !validateLoginConfig({ ...goodLogin, steps: [{ selector: '#u', action: 'type' }] }).ok);
ok('a literal type step with no literal is rejected',
  !validateLoginConfig({ ...goodLogin, steps: [{ selector: '#u', action: 'type', value_ref: 'literal' }] }).ok);
ok('an unknown action is rejected',
  !validateLoginConfig({ ...goodLogin, steps: [{ selector: '#u', action: 'frobnicate' }] }).ok);
ok('a type step with no selector is rejected',
  !validateLoginConfig({ ...goodLogin, steps: [{ action: 'type', value_ref: 'username' }] }).ok);
ok('a url success probe with no value is rejected',
  !validateLoginConfig({ ...goodLogin, success: { kind: 'url' } }).ok);
ok('a bearer success probe needs no value', validateLoginConfig({ ...goodLogin, success: { kind: 'bearer' } }).ok);
ok('an unknown success probe kind is rejected',
  !validateLoginConfig({ ...goodLogin, success: { kind: 'telepathy' } }).ok);

// --- the fill-sequence interpreter resolves creds and never exposes the password in a label ---
const plan = buildLoginPlan(goodLogin, { username: 'alice', password: 's3cr3t-pw' });
ok('plan has one instruction per step', plan.length === goodLogin.steps.length);
ok('username step resolves to the stored username', plan[0].value === 'alice');
ok('password step resolves to the stored password', plan[1].value === 's3cr3t-pw');
ok('the password step is marked secret', plan[1].secret === true);
ok('a non-password step is not marked secret', plan[0].secret === false);
ok('NO plan label contains the password value', plan.every((i) => !String(i.label).includes('s3cr3t-pw')));
ok('a literal step resolves to its literal, not a credential',
  buildLoginPlan({ steps: [{ selector: '#x', action: 'type', value_ref: 'literal', literal: 'LIT' }] },
    { username: 'a', password: 'b' })[0].value === 'LIT');
ok('a missing credential resolves to empty, never undefined',
  buildLoginPlan({ steps: [{ selector: '#u', action: 'type', value_ref: 'username' }] }, {})[0].value === '');

// --- login_url egress is fail-closed, reusing the same allowlist match ---
ok('login_url on an allowed in-scope host passes', loginUrlAllowed(goodLogin, allow));
ok('login_url on an allowed auth host passes',
  loginUrlAllowed({ login_url: 'https://cognito-idp.us-east-1.amazonaws.com/' }, allow));
ok('login_url on an off-scope host is REFUSED', !loginUrlAllowed({ login_url: 'https://evil.example.com/login' }, allow));
ok('login_url against an empty allowlist is refused (fail closed)', !loginUrlAllowed(goodLogin, []));
ok('a junk login_url is refused', !loginUrlAllowed({ login_url: 'not a url' }, allow));

console.log(`${pass} passed, 0 failed`);
