// GUIDANCE: analysis, threat model, auth, authorization and flows.
//
// One entry per MCP tool in this domain, keyed by the name index.js registers. The wrapper looks an
// entry up by (tool name, params.action), merges any per-action override over the tool-level entry,
// and attaches the result to the response. See guidance/index.js for the merge and session.js for
// the teach-once-then-remind delivery.
//
// WHAT THESE TOOLS HAVE IN COMMON, and why the "lies" field reads differently here than it does for
// the scanners. Nothing in this file finds anything. Every one of these tools reports on state the
// OPERATOR created: a threat somebody wrote, a token somebody pasted, a flow somebody assembled, a
// rule somebody typed. So the failure mode is almost never a false negative from a scan that did
// not run. It is a stale view, an id from the wrong namespace, or a partial write that blanked the
// columns it did not mention. Those three account for nearly every incident this estate has
// recorded in this area, so they are what the "lies" fields say.
//
// The step names come from steps.js, which abbreviates server/utils/methodology.go in its own Order:
// manual-crawl(10), content-discovery(20), archive-discovery(30), parameter-discovery(40),
// consolidate-vectors(50), vector-scanning(60), access-bypass(70), threat-model(80). Inventing a step
// name here would put this file in direct contradiction with get_methodology, which reads from that
// same Go map, and spelling one differently from recon.js puts it in contradiction with the rest of
// this registry, which is what had already happened before the labels were shared.

const {
  CRAWL: S_CRAWL,
  ARCHIVE: S_ARCHIVE,
  CONSOLIDATE: S_CONSOLIDATE,
  SCANNING: S_SCANNING,
  BYPASS: S_BYPASS,
  THREAT: S_THREAT,
} = require('./steps');

module.exports = {

  // === analysis.js ==============================================================================

  find_high_value_targets: {
    step: S_CRAWL,
    tool: 'Ranks the discovered URLs by ROI score and pulls out the ones with SSL problems or an ' +
      'admin-flavoured technology (Jenkins, Grafana, Swagger, phpMyAdmin). It proves which host is ' +
      'worth spending a manual crawl on, not that anything is vulnerable.',
    lies: 'ROI is computed from what the earlier scans happened to record, so a host nobody probed ' +
      'scores zero and reads as uninteresting. An empty result means no URL has a score yet, which ' +
      'is a statement about your scans and not about the target.',
    next: 'query_target_urls, then manage_scope_rules and run_url_workflow',
    learn: 'kb://methodology/recon-methodology',
    derived: true,
  },

  search_all: {
    step: S_CONSOLIDATE,
    tool: 'Substring search across four stored corpora at once: consolidated subdomains, target ' +
      'URLs, company domains and nuclei results. The cheap way to answer "have we seen this string ' +
      'anywhere" before opening any single section.',
    lies: 'Each of the four queries is wrapped in its own try/catch and a category that errors is ' +
      'simply omitted, so a missing key means "that query failed or matched nothing" and the two ' +
      'are indistinguishable. It also searches only these four tables, so a hit living in captures, ' +
      'endpoints or vector findings will not appear.',
    next: 'search_global, query_endpoints, or replay_request action:"search_captures"',
    derived: true,
  },

  // === scoperules.js ============================================================================

  manage_scope_rules: {
    step: S_CRAWL,
    tool: 'Authors the pattern-capable boundary that decides what the crawl records and what every ' +
      'scanner is allowed to contact: exact hosts, whole subtrees, subdomains-only, substring and ' +
      'regex, with denies that beat every allow.',
    vuln: 'Not a vulnerability check. It is the control that keeps an engagement inside the ' +
      'programme, and the thing that decides whether a real finding was even reachable.',
    lies: 'A boundary that is too narrow produces silence that looks like a clean target: on one ' +
      'live target 1,850 of 1,872 candidate endpoints were unsendable purely because they sat on ' +
      'hosts outside the rules. Read the blast radius from preview, never assume a rule is narrow ' +
      'because it looks narrow.',
    next: 'manage_flow_config action:"endpoint_summary", then run_url_workflow',
    learn: 'kb://methodology/recon-methodology',
    derived: false,
    actions: {
      syntax: {
        tool: 'Returns the rule grammar with no round trip and no arguments. Call it before writing ' +
          'your first rule rather than guessing at the operators.',
        next: 'manage_scope_rules action:"preview"',
      },
      preview: {
        tool: 'Parses a rule WITHOUT storing it and reports the sentence it renders as, its blast ' +
          'radius, and which already-recorded hosts it would newly allow or newly deny.',
        lies: 'It can only compare against hosts already in the database, so "newly allows: 0" says ' +
          'nothing about the hosts a wide rule would admit tomorrow. That is exactly why a wide ' +
          'rule still needs confirm_wide even after a clean preview.',
        next: 'manage_scope_rules action:"add"',
      },
      add: {
        tool: 'Stores a rule. A rule whose blast radius is "wide" is refused unless confirm_wide ' +
          'carries its exact canonical text, which is quoted back to you in the refusal.',
        lies: 'confirm_wide is the canonical text rather than a boolean precisely so a rule cannot ' +
          'be confirmed by accident or in place of a different one. Copying the string from an ' +
          'older refusal confirms that older rule, not this one.',
        next: 'manage_scope_rules action:"list"',
      },
      disable: {
        tool: 'Switches a stored rule off without losing its text, which is how you narrow the ' +
          'boundary for one scan and put it back afterwards.',
        lies: 'Disabling an allow does not automatically deny what it covered: the legacy host list ' +
          'still applies when no rule is left enabled, so check list afterwards rather than ' +
          'assuming the boundary shrank.',
        next: 'manage_scope_rules action:"list"',
      },
    },
  },

  // === notes.js =================================================================================

  manage_notes: {
    step: S_THREAT,
    tool: 'Free-text notes on a whole scope target: working theories, what has already been tried, ' +
      'what to come back to. Nothing scans these and no other tool reads them, which is what makes ' +
      'them the right home for reasoning that has no schema.',
    lies: 'list returns a CLIPPED preview of each body, not the body, so a note whose substance ' +
      'sits past the cut looks empty in a listing. Find the note in list, then read it with get.',
    next: 'manage_threat_model action:"add_note" for reasoning about one threat',
    derived: false,
    actions: {
      list: {
        tool: 'The notes on a target, newest edit first, each with a clipped preview. The pattern ' +
          'filter searches the FULL body even though only a preview comes back, so it finds notes ' +
          'whose match sits past the preview cut.',
        next: 'manage_notes action:"get"',
      },
      update: {
        tool: 'Changes a note title or content. Either alone is enough; the other is read back and ' +
          'preserved.',
        lies: 'content replaces the existing body wholesale and an explicit empty string is honoured ' +
          'as deliberate blanking rather than as "not supplied". Passing target_id as well saves one ' +
          'request per target, because without it the note is found by asking every target.',
        next: 'manage_notes action:"get"',
      },
    },
  },

  // === threatmodel.js ===========================================================================

  manage_threat_model: {
    step: S_THREAT,
    tool: 'The STRIDE threat model: one row per claim about how the application could be abused, ' +
      'plus the flows that demonstrate it and the ad hoc notes recording what testing actually ' +
      'showed. A threat is a hypothesis with a test attached, not a finding.',
    vuln: 'This is where access control and business logic bugs are caught, because they have no ' +
      'signature a scanner can match: a successful IDOR looks like an ordinary 200 and is only ' +
      'findable if the intended rule was written down first.',
    lies: 'Every PUT here replaces the row wholesale, so a partial update blanks what it did not ' +
      'restate. A 58 row backfill sending only category, url and authenticated destroyed seven ' +
      'other columns on every row, and the drift check missed it because it compared only the ' +
      'fields that had been touched.',
    next: 'manage_threat_model_notes, manage_flow_builder, or replay_request',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
    actions: {
      list: {
        tool: 'Every threat on a target with a count per STRIDE category, so you can see which ' +
          'parts of the model are empty before spending a read on any of them.',
        lies: 'A category showing zero usually means nobody modelled it, not that the target is ' +
          'safe there. Spoofing and elevation of privilege are the two the tools cannot help with ' +
          'at all, so they are the two most often left empty.',
        next: 'manage_threat_model action:"create" for the empty categories',
      },
      create: {
        tool: 'Adds one threat under one STRIDE category. It must name an attack via attack_id or ' +
          'attack_custom_name or the POST refuses it.',
        lies: 'mechanism and target_object are TITLE fragments, not prose: the card header is ' +
          'composed as "<attack> - <mechanism> on <target_object>" and capped at 125 characters ' +
          'together. steps must be a serialised JSON ARRAY of strings or the reproduction renders ' +
          'as one unreadable item, and an empty summary renders a blank card.',
        next: 'manage_threat_model action:"link_flow", then manage_flow_builder',
      },
      update: {
        tool: 'Changes a threat. Pass target_id as well: that is what lets the current row be read ' +
          'back and merged underneath your fields, because the route itself replaces every column.',
        lies: 'Without the read-back merge a partial update blanks the columns it did not mention, ' +
          'which is how seven columns were wiped on 58 rows in one call. A verification that checks ' +
          'only the fields you sent proves nothing; diff the whole row.',
        next: 'manage_threat_model action:"list"',
      },
      delete: {
        tool: 'Removes one threat. Its notes go with it.',
        lies: 'There is no soft delete and no restore, and there are no database backups here. A ' +
          'threat deleted by mistake is recoverable only from session transcripts.',
        next: 'manage_threat_model action:"list"',
      },
      link_flow: {
        tool: 'Records that a flow demonstrates a threat, which is what turns a claim into ' +
          'evidence. Linking the same pair twice updates the note rather than creating a second ' +
          'link.',
        lies: 'The flow side is NOT a foreign key, so a link to a flow that no longer exists is ' +
          'accepted silently. It takes both id shapes: a built flow is a UUID, a detected flow is ' +
          'the composite <session>~<tab>~<root capture>, and neither is validated.',
        next: 'manage_threat_model action:"list_flow_links"',
      },
      list_flow_links: {
        tool: 'Every flow mapped to a threat on this target, each carrying the threat mechanism and ' +
          'STRIDE category and the flow own name.',
        lies: 'Because the flow side is not a foreign key, every read resolves ids against the ' +
          'current flow list and marks the ones that do not resolve. An unresolved link means the ' +
          'evidence is gone, not that the threat was retracted.',
        next: 'manage_detected_flows action:"list" or manage_flow_builder action:"list_flows"',
      },
      add_note: {
        tool: 'Attaches a note to ONE threat, addressed by threat_id. This is where the working ' +
          'goes: what was tried, what came back, which precondition could not be met.',
        lies: 'Three note stores exist and they are easy to confuse. This one hangs off a single ' +
          'threat; manage_threat_model_notes holds the four supporting collections for the model as ' +
          'a whole; manage_notes is the whole-target note.',
        next: 'manage_threat_model action:"update" to set test_status',
      },
      list_notes: {
        tool: 'Every note on one threat, most recently edited first, each with a clipped preview ' +
          'rather than the body. Addressed by threat_id.',
        lies: 'The addressing flips one level down: list and add take threat_id, update and delete ' +
          'take the note own note_id. A threat id passed where a note id belongs reports as the ' +
          'note not existing, not as the wrong kind of id.',
        next: 'manage_threat_model action:"update_note"',
      },
      update_note: {
        tool: 'Changes a note title, body or both, addressed by note_id.',
        lies: 'Unlike the threat update this route is COALESCE-guarded in Go, so whatever you leave ' +
          'out is preserved by the route itself and there is no read-back merge. Copying the merge ' +
          'dance from the threat update here would reintroduce the race the SQL guard removes.',
        next: 'manage_threat_model action:"list_notes"',
      },
    },
  },

  manage_threat_model_notes: {
    step: S_THREAT,
    tool: 'The four supporting collections a threat is built out of: application question answers, ' +
      'mechanism examples, notable objects and security control notes. A threat names a mechanism, ' +
      'a target object and its controls BY NAME, so a threat pointing at something nobody ' +
      'documented is a threat nobody can act on.',
    lies: 'The grouping names are free text and are not checked against the lists the modals offer, ' +
      'so a typo silently creates a new group instead of erroring, and the collection then looks ' +
      'sparser than it is.',
    next: 'manage_threat_model action:"create"',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
    actions: {
      list: {
        tool: 'Every row in one collection on a target, with a count per grouping name. Pass name ' +
          'to narrow to one group.',
        next: 'manage_threat_model_notes action:"create"',
      },
      update: {
        tool: 'Changes a row, addressed by its own row_id. For mechanisms and notable_objects pass ' +
          'target_id too so the current row can be read back and merged.',
        lies: 'The mechanisms and notable_objects routes replace more than one column, so a partial ' +
          'update without target_id blanks what it did not restate. These rows are only readable ' +
          'per target: there is no route that fetches one by its own id.',
        next: 'manage_threat_model_notes action:"list"',
      },
      create: {
        tool: 'Adds a row under a grouping name. The column each field writes differs per ' +
          'collection: name is the question text, mechanism name, object name or control name, and ' +
          'content is the answer, notes, JSON example or note respectively.',
        lies: 'notable_objects expects a pasted JSON example in content, and mechanisms expect a ' +
          'short mechanism name rather than prose, for the same reason threat mechanisms do: these ' +
          'names become labels a human scans.',
        next: 'manage_threat_model action:"create"',
      },
    },
  },

  // === urlresults.js ============================================================================

  get_discovered_endpoints: {
    step: S_ARCHIVE,
    tool: 'The endpoints one crawler found on this target, which is exactly what that tool Results ' +
      'modal shows. Give it a target and a tool name and it resolves the newest successful scan ' +
      'itself.',
    lies: 'katana and gospider actively crawl and linkfinder reads JavaScript, but gau and ' +
      'waybackurls are ARCHIVE lookups that never touch the target, so an archive hit proves a URL ' +
      'existed once and not that it exists now. Omitting scan_id reads the newest run, so a small ' +
      'recent run hides a large older one.',
    next: 'consolidate_endpoints, then manage_endpoints',
    learn: 'kb://methodology/recon-methodology',
    derived: true,
  },

  manage_attack_surface_assets: {
    step: S_CONSOLIDATE,
    tool: 'The consolidated attack surface for a target: ASNs, network ranges, IPs, FQDNs, cloud ' +
      'assets and live web servers, readable as counts or as rows, with hand additions for ' +
      'anything enumeration never found.',
    lies: 'A later Consolidate Attack Surface run REBUILDS the whole set from the scan tables, so ' +
      'deleting an asset that a scan still reports brings it straight back. To make a removal stick ' +
      'you have to fix whatever discovered it.',
    next: 'query_attack_surface_assets, or manage_scope_rules',
    derived: true,
    actions: {
      counts: {
        tool: 'How many assets of each type exist. Cheap, and the right first call, because the ' +
          'full list runs to thousands of rows.',
        next: 'manage_attack_surface_assets action:"list"',
      },
      add: {
        tool: 'Records something consolidation never found, for example a host named on a programme ' +
          'scope page that no enumeration source returns.',
        lies: 'The value is validated against asset_type, so a mistyped CIDR is rejected rather ' +
          'than stored wrong, but a value added under the wrong type is accepted if it parses. Use ' +
          'asset_identifiers to add several at once: each is added independently so one bad value ' +
          'does not lose the rest.',
        next: 'manage_attack_surface_assets action:"counts"',
      },
    },
  },

  manage_client_identifiers: {
    step: S_THREAT,
    tool: 'The identifier values a caller might be able to change, harvested from traffic already ' +
      'captured or added by hand. These are the raw candidates that Client Identity Patterns later ' +
      'promotes into a documented pattern.',
    vuln: 'Every candidate here is an IDOR test waiting to be run: the value you would swap for ' +
      'another account equivalent to see whether the server checks who is asking.',
    lies: 'auto_detect reads only STORED captures and sends nothing, so its output is bounded by ' +
      'how thoroughly the manual crawl was done. A feature nobody exercised produced no capture, so ' +
      'it yields no candidate and reads as having no identifiers at all.',
    next: 'manage_identity_patterns action:"create"',
    learn: 'kb://reports/accepted/idor-reports',
    derived: false,
    actions: {
      auto_detect: {
        tool: 'Sweeps every capture recorded for this target and records each value shaped like an ' +
          'object reference. Costs nothing at the target, so run it as soon as a crawl has ' +
          'recorded anything.',
        lies: 'It is shape matching, so version strings and locale codes come back as candidates ' +
          'and a non-obvious id (base64, a composite key, one buried in a custom header) does not. ' +
          'Delete the noise and add the misses by hand.',
        next: 'manage_client_identifiers action:"list", then manage_identity_patterns',
      },
      create: {
        tool: 'Records a candidate by hand, which is what selecting a value in the Client Identity ' +
          'modal does. endpoint_url is required because an identifier is only meaningful with the ' +
          'request it appeared in.',
        lies: 'The same UUID in a URL path and in a response body are two different testing ' +
          'opportunities, not a duplicate. source:"decoded" is the signed-token case, which is the ' +
          'one worth checking for a missing signature check first.',
        next: 'manage_identity_patterns action:"create"',
      },
    },
  },

  // === authz.js =================================================================================

  manage_identity_patterns: {
    step: S_THREAT,
    tool: 'Documents HOW the server decides who is asking, each pattern backed by one real request ' +
      'and the response it got, and replays them to check the mechanism is still the one in front ' +
      'of you.',
    vuln: 'The category is the whole point because it says whether the endpoint is worth attacking. ' +
      'parameter means the caller sets the id directly and is the best IDOR target; signed_token ' +
      'needs a signature failure first; user_context_object leaves the attacker nothing to move.',
    lies: 'Patterns are only readable per target, so get needs target_id as well as pattern_id and ' +
      'a lone pattern id reports as not found. Editing raw_request does NOT re-send it, so the ' +
      'recorded response can describe bytes that are no longer the ones stored.',
    next: 'manage_policy_access, manage_role_access, or manage_flow_builder to test one',
    learn: 'kb://reports/accepted/idor-reports',
    derived: false,
    actions: {
      list: {
        tool: 'Every identity pattern on a target, best IDOR targets first, which means the ' +
          'parameter-category ones lead.',
        next: 'manage_identity_patterns action:"get"',
      },
      replay: {
        tool: 'Re-sends the stored raw_request and overwrites the recorded response with what comes ' +
          'back. This is how you check the identity mechanism you modelled is still live.',
        lies: 'It puts real traffic on the target and it overwrites the evidence you had. If the ' +
          'session token behind the stored request has since expired, the replay records a login ' +
          'wall and the pattern now documents the wall rather than the application.',
        next: 'check_session_tokens action:"validate" first, then manage_identity_patterns',
      },
    },
  },

  manage_policy_access: {
    step: S_THREAT,
    tool: 'Models an application that grants each permission individually: the entity permissions ' +
      'are granted on, its full permission list, and specific configured instances such as "Bob, ' +
      'read only".',
    vuln: 'Broken access control on a per-permission system, where the bug is usually one ' +
      'permission the server never actually checks.',
    lies: 'A setting can be allow, deny or UNSET, and unset is deliberately not deny: never granted ' +
      'and explicitly revoked behave differently often enough to be worth separating. A permission ' +
      'you did not model is a permission nobody will test, so enumerate the ones you expect nobody ' +
      'to have too.',
    next: 'manage_role_access, get_authz_summary, or manage_flow_builder',
    derived: true,
    actions: {
      list: {
        tool: 'Every policy entity with its permissions and its instances, or one entity when ' +
          'entity_id is given. There is no route that fetches an entity on its own.',
        next: 'manage_policy_access action:"add_permission"',
      },
      delete_entity: {
        tool: 'Removes the entity and takes its permissions, instances and settings with it.',
        lies: 'Deleting a permission alone also removes its setting on every instance, so a ' +
          'rename done as delete-then-add silently discards every configured value for it.',
        next: 'manage_policy_access action:"list"',
      },
      set_settings: {
        tool: 'Writes the value of one or more permissions on one instance. Pass target_id when ' +
          'addressing settings by permission_key rather than permission_id.',
        lies: 'A permission left out of the payload keeps what it had, so this cannot be used to ' +
          'reset an instance; write the unset value explicitly if that is what you mean.',
        next: 'manage_policy_access action:"list"',
      },
    },
  },

  manage_role_access: {
    step: S_THREAT,
    tool: 'Models role-based access as a matrix of roles by actions, each cell can_do, cannot_do or ' +
      'forbidden_to_do.',
    vuln: 'Privilege escalation and horizontal access control. forbidden_to_do means the role must ' +
      'never perform the action under any circumstances, and is the only value whose violation is ' +
      'automatically a finding.',
    lies: 'The model records what the application CLAIMS, never what it does, so a filled matrix ' +
      'with zero forbidden cells is a model that generates no tests. Deleting a role removes its ' +
      'whole row of cells and deleting an action removes its whole column, with no warning about ' +
      'how many settings that discards.',
    next: 'manage_flow_builder to test a forbidden cell, then manage_threat_model action:"create"',
    learn: 'kb://methodology/web-app-methodology',
    derived: true,
    actions: {
      get: {
        tool: 'The roles, the actions and the cell for every pair, with the forbidden cells pulled ' +
          'out separately because those are the ones that become findings.',
        next: 'manage_role_access action:"set_matrix", or manage_flow_builder',
      },
      set_matrix: {
        tool: 'Writes one or more cells. Pairs left out keep what they have, and the response ' +
          'reports how many cells landed on each value.',
        lies: 'Every forbidden_to_do cell you write is a claim that still has to be falsified. The ' +
          'count in the response is the number of tests you just created, not the number you ran.',
        next: 'manage_flow_builder action:"seed_from_detected_flow"',
      },
    },
  },

  manage_discretionary_access: {
    step: S_THREAT,
    tool: 'Models access a holder can pass on, up to their own level: a shared document or board ' +
      'where an admin can invite admins but a user can only invite users. Levels carry a rank and a ' +
      'grant ceiling.',
    vuln: 'Privilege escalation through sharing. A holder who manages to grant a level above its ' +
      'ceiling is the escalation the whole object exists to model.',
    lies: 'Ranks are only ever compared with each other, so 1 and 2 say everything 10 and 20 would ' +
      'and absolute values mean nothing. can_grant:false is a stronger claim than a ceiling of ' +
      'zero, and both are tested by trying to share anyway rather than by reading the model back.',
    next: 'manage_flow_builder to attempt the grant, then manage_threat_model action:"create"',
    derived: true,
    actions: {
      list: {
        tool: 'Every DAC object with its levels in rank order, and for each level the levels it ' +
          'should be able to grant and the ones where granting would be an escalation.',
        lies: 'The escalation list is derived from the ceilings you typed in, so it describes the ' +
          'documented rule and not the observed behaviour. It is a list of experiments to run.',
        next: 'manage_flow_builder action:"create_flow"',
      },
      delete_object: {
        tool: 'Removes the object and takes its levels with it.',
        next: 'manage_discretionary_access action:"list"',
      },
    },
  },

  get_authz_summary: {
    step: S_THREAT,
    tool: 'Counts across all four authorization sections at once: identity patterns by category, ' +
      'policy entities and permissions, roles and actions and forbidden cells, discretionary ' +
      'objects and levels. The cheapest way to learn what has been modelled before spending calls ' +
      'on the four listing tools.',
    lies: 'These are counts of what somebody WROTE DOWN, not of what the application has. A zero ' +
      'anywhere means nobody modelled that section, and a section with rows but zero forbidden ' +
      'cells or zero parameter-category patterns generates no tests at all.',
    next: 'manage_identity_patterns, manage_role_access, or manage_policy_access',
    derived: false,
  },

  // === authsessions.js ==========================================================================

  manage_auth_flows: {
    step: S_CRAWL,
    tool: 'The consolidated auth flow tool: create, read, update and delete a register, login, ' +
      'MFA, magic link or reset sequence and its ordered steps, and replay it. A flow is what makes ' +
      'a session token refreshable when it expires.',
    vuln: 'Not a scan. It is the prerequisite for every authenticated test: without a working flow ' +
      'an expired token turns the entire application into a login wall that the scanners will ' +
      'happily fingerprint as the application.',
    lies: 'replay honours NO exclusion list and NO scope boundary. server/utils/authFlowsUtils.go ' +
      'contains no scope check at all, so a stored step whose Host is out of scope will be sent ' +
      'there, and auth_flow_steps has no enabled column so a single dangerous step cannot be ' +
      'switched off. Deleting the step is the only real control.',
    next: 'manage_session_tokens action:"parse", then check_session_tokens action:"validate"',
    derived: false,
    actions: {
      get: {
        tool: 'One flow and its steps in order, with the response each step last recorded. Pass ' +
          'step_id to read a single step at a much larger body budget.',
        lies: 'Recorded response bodies are CLIPPED per row and the budget is divided by the row ' +
          'count, so a value you need can sit past the cut: pulling a CSRF token out of a captured ' +
          'login form failed because it sat at character 3500 of a 7492 character page. Read one ' +
          'step, or search the body directly.',
        next: 'manage_auth_flows action:"replay"',
      },
      add_step: {
        tool: 'Appends a raw HTTP request as the next step and by default SENDS IT NOW, recording ' +
          'the live response. Placeholders of the form {{af:NAME}} pull in values an earlier step ' +
          'captured, and Content-Length is recomputed afterwards.',
        lies: 'The unresolved-placeholder refusal is an accident, not a control: the standard ' +
          'advice is to paste a live token in when testing begins, which removes the guard at ' +
          'exactly the moment a replay becomes plausible. Set replay:false to store a request ' +
          'without sending it.',
        next: 'manage_auth_flows action:"get"',
      },
      delete_step: {
        tool: 'Removes one step. The remaining steps keep their numbers, so follow with ' +
          'reorder_steps if the gap matters.',
        lies: 'This is the ONLY reliable way to stop a dangerous step firing, because there is no ' +
          'enabled flag and no scope check on replay. Keep the removed request as prose in the flow ' +
          'description if you need the record.',
        next: 'manage_auth_flows action:"reorder_steps"',
      },
      replay: {
        tool: 'Re-sends the flow end to end with one shared cookie jar, or one step with step_id, ' +
          'and overwrites the recorded response on every step it runs.',
        lies: 'It sends real traffic and it is unguarded: no exclusion row, no scope rule and no ' +
          '"DO NOT REPLAY" in the name will stop it. Running it in a loop can trip rate limiting or ' +
          'an account lockout, because it is a full login sequence each time.',
        next: 'check_session_tokens action:"validate"',
      },
      delete: {
        tool: 'Deletes the flow and cascades its steps. Any session token pointing at it keeps ' +
          'working but loses the flow that could reissue it.',
        next: 'manage_session_tokens action:"list"',
      },
    },
  },

  manage_auth_recording: {
    step: S_CRAWL,
    tool: 'Records an authentication flow as it happens, or inspects and imports one the browser ' +
      'extension recorded, then turns the included requests into an auth flow with one step each.',
    lies: 'A recording captures EVERY request in order regardless of scope, because an auth flow ' +
      'routinely crosses to an identity provider on another domain. That is deliberate, but it ' +
      'means an unreviewed import can create steps aimed at third-party hosts, and replay does not ' +
      'check scope.',
    next: 'manage_auth_flows action:"get", then check_session_tokens action:"validate"',
    derived: true,
    actions: {
      start: {
        tool: 'Opens a recording. The browser extension polls for the open one and streams into it, ' +
          'so starting one here is also how you hand a recording to a human at the keyboard.',
        lies: 'There is one open recording per target, so starting a second is not a parallel ' +
          'capture. Use heartbeat to keep an idle recording alive rather than restarting it.',
        next: 'manage_auth_recording action:"status"',
      },
      capture: {
        tool: 'Pushes requests into an open recording directly. This is the path that needs no ' +
          'extension at all: start, capture what you sent, stop, import.',
        next: 'manage_auth_recording action:"stop"',
      },
      requests: {
        tool: 'The captured requests in order, which is where you work out which ones are the auth ' +
          'flow and which are page furniture.',
        lies: 'Analytics beacons, font loads and prefetches sit in this list looking exactly like ' +
          'flow steps. Import everything and the flow replays a dozen irrelevant requests at the ' +
          'target every time it runs.',
        next: 'manage_auth_recording action:"set_included"',
      },
      set_included: {
        tool: 'Marks requests in or out. Excluded requests stay in the recording and are skipped on ' +
          'import, because deleting them would break the sequence and the sequence is what makes a ' +
          'replay reproduce the flow.',
        next: 'manage_auth_recording action:"import"',
      },
      import: {
        tool: 'Turns the included requests into an auth flow with one step each.',
        lies: 'The imported steps carry whatever tokens and CSRF values were live at recording ' +
          'time, hardcoded. Convert the per-request ones into {{af:NAME}} extractions or the second ' +
          'replay fails on a stale token and looks like a broken login.',
        next: 'manage_auth_flows action:"get"',
      },
    },
  },

  manage_session_tokens: {
    step: S_CRAWL,
    tool: 'The tokens every other scan sends: create, read, update, delete, switch active, and ' +
      'parse a raw Set-Cookie line, Cookie header or Authorization header into properly scoped ' +
      'tokens. Only ACTIVE tokens within their scope_domains are attached to traffic.',
    lies: 'A valid credential is not always enough. On a load-balanced target the session store can ' +
      'be per backend, so the session cookie alone gets a 302 to login while the same request with ' +
      'the routing cookie gets a 200; register that companion cookie with token_role:"companion" or ' +
      'every authenticated scan silently runs as anonymous.',
    next: 'check_session_tokens action:"validate", then run_endpoint_scan',
    derived: false,
    actions: {
      parse: {
        tool: 'Hand it a raw HTTP request, a curl command or a block of Set-Cookie headers and it ' +
          'returns the tokens found in it, tied to the flow that produced them.',
        lies: 'It returns everything that looks like a token, including routing and analytics ' +
          'cookies. AWSALB, AWSALBCORS, JSESSIONID routing suffixes and __Host- affinity cookies ' +
          'are not credentials but are often REQUIRED alongside one, so file them as companions ' +
          'rather than discarding them.',
        next: 'manage_session_tokens action:"create"',
      },
      create: {
        tool: 'Stores a token with the domains it may be sent to. token_role is credential by ' +
          'default, or companion for a routing or affinity cookie that must ride along.',
        lies: 'A companion is never graded on its own and is attached to BOTH the credential arm ' +
          'and the anonymous control arm, so the comparison still differs by exactly one thing. ' +
          'Leaving a companion off the control arm manufactures a false active verdict.',
        next: 'manage_session_tokens action:"activate"',
      },
      activate: {
        tool: 'Starts sending this token on scans within its scope_domains.',
        lies: 'Activation is what makes a scan authenticated, so a section that reports clean while ' +
          'no token was active tested the login wall. Check what is active before reading any scan ' +
          'result as coverage.',
        next: 'check_session_tokens action:"validate_all"',
      },
      deactivate: {
        tool: 'Stops sending a token without deleting it. Reach for this when a scan is ' +
          'fingerprinting the login wall instead of the application.',
        next: 'manage_session_tokens action:"list"',
      },
      events: {
        tool: 'The validate and refresh history for one token, newest first.',
        lies: 'A long run of successful validates says the probe URL still differentiates by auth ' +
          'state, not that the token is good for the endpoints you care about.',
        next: 'check_session_tokens action:"validate"',
      },
    },
  },

  check_session_tokens: {
    step: S_SCANNING,
    tool: 'Sends a real authenticated request and reports whether the target still honours the ' +
      'token, and refreshes dead ones by replaying the auth flow they are tied to. Separate from ' +
      'the CRUD tool precisely because these actions put traffic on the target.',
    lies: 'not_honoured reads as "dead credential" and frequently is not. On a load-balanced target ' +
      'a perfectly valid session returns not_honoured purely because the routing cookie was missing ' +
      'from the request; look for a per-response backend header before touching the auth flow.',
    next: 'manage_session_tokens action:"create" for the companion cookie, then run_endpoint_scan',
    derived: false,
    actions: {
      validate: {
        tool: 'Sends one authenticated request with this token and reports what came back. This is ' +
          'the check to run BEFORE a scan, because an expired token turns every endpoint into a ' +
          'login wall.',
        lies: 'The verdict is a comparison between an authenticated arm and an anonymous control, ' +
          'so it is only as good as the probe URL: a page that does not differ by auth state ' +
          'reports not_honoured for a live session. A companion token reports status companion, ' +
          'never not_honoured, because grading it alone would be meaningless.',
        next: 'run_endpoint_scan or run_url_workflow',
      },
      refresh: {
        tool: 'Replays the token auth flow and stores the new value it issues. Needs the token to ' +
          'carry an auth_flow_id.',
        lies: 'A refresh can report success without setting a value: the flow ran and no token was ' +
          'extracted from it, which is indistinguishable from success by the status alone, so read ' +
          'new_value_set. It sends an entire login sequence, so a loop can trip rate limiting or an ' +
          'account lockout.',
        next: 'check_session_tokens action:"validate"',
      },
      validate_all: {
        tool: 'Validates every active token on a target one at a time. Pass include_inactive to ' +
          'check one before activating it.',
        next: 'manage_session_tokens action:"activate"',
      },
    },
  },

  // === authflows.js, the granular per-route tools ===============================================
  //
  // These predate manage_auth_flows and cover the same ten routes one call at a time. Kept because
  // the muscle memory and existing scripts use them; prefer manage_auth_flows for new work.

  list_auth_flows: {
    step: S_CRAWL,
    tool: 'Lists a target documented authentication flows with their step counts, optionally ' +
      'filtered to one category. The cheapest way to find out whether a login has been modelled at ' +
      'all before trying to authenticate anything.',
    lies: 'A flow with steps is not a flow that works: the step count says somebody wrote requests ' +
      'down, not that a replay still produces a session.',
    next: 'get_auth_flow_steps, or manage_auth_flows action:"get"',
    derived: true,
  },

  create_auth_flow: {
    step: S_CRAWL,
    tool: 'Creates an empty flow in one of the five categories, optionally tagging the auth ' +
      'mechanism and a base_url the steps replay against.',
    lies: 'base_url is a fallback, not an override: a step Host header always wins, which is what ' +
      'lets a flow cross to an identity provider and also what lets it leave your scope.',
    next: 'add_auth_flow_step',
    derived: true,
  },

  update_auth_flow: {
    step: S_CRAWL,
    tool: 'Changes a flow name, description, auth_type, base_url or category. Only pass the fields ' +
      'you want changed.',
    lies: 'category is one of five values matching the database constraint, the Go validator, the ' +
      'recorder and the UI. magic_link was once missing from the client enum, which blocked every ' +
      'update of an imported magic-link flow because the client sends the category back each time.',
    next: 'get_auth_flow_steps',
    derived: true,
  },

  delete_auth_flow: {
    step: S_CRAWL,
    tool: 'Deletes a flow and cascades all of its steps.',
    lies: 'Session tokens pointing at this flow keep working and silently lose the only thing that ' +
      'could reissue them, so the failure surfaces later as a refresh that cannot run.',
    next: 'manage_session_tokens action:"list"',
    derived: true,
  },

  get_auth_flow_steps: {
    step: S_CRAWL,
    tool: 'The ordered steps of a flow with each recorded response. Pass step_id to read one step ' +
      'at a much larger body budget, or body_match to get the window around a string.',
    lies: 'raw_request is OMITTED from a multi-step listing rather than clipped, on purpose. This ' +
      'shape round-trips into update_auth_flow_step, which replaces the stored request wholesale, ' +
      'so a truncated raw_request handed back would become a truncated request the replay engine ' +
      'later fires at the target as if it were real.',
    next: 'replay_auth_flow_step, or update_auth_flow_step',
    derived: true,
  },

  add_auth_flow_step: {
    step: S_CRAWL,
    tool: 'Adds a step from full raw HTTP bytes and by DEFAULT sends it to the target and records ' +
      'the live response. {{af:NAME}} placeholders pull in values an earlier step captured and ' +
      'Content-Length is recomputed afterwards.',
    vuln: 'The extractions array is what makes a per-request CSRF token work: step one captures the ' +
      'token with an RE2 regex whose group 1 is the value, step two spends it. A required capture ' +
      'that does not match stops the later steps rather than sending a blank token.',
    lies: 'It sends by default. Pass replay:false to store a request without putting it on the ' +
      'wire, and remember that nothing here checks scope or the exclusion list.',
    next: 'get_auth_flow_steps, then replay_auth_flow',
    derived: true,
  },

  update_auth_flow_step: {
    step: S_CRAWL,
    tool: 'Changes a step raw request, name or position. It does NOT re-send it.',
    lies: 'The route replaces the stored request wholesale, so passing a raw_request that came back ' +
      'truncated from a listing stores the truncated bytes permanently. Read the step with step_id ' +
      'first, which is the path that returns raw_request in full.',
    next: 'replay_auth_flow_step',
    derived: true,
  },

  delete_auth_flow_step: {
    step: S_CRAWL,
    tool: 'Removes a step from a flow.',
    lies: 'Because there is no enabled column on auth flow steps and replay ignores every exclusion ' +
      'and scope rule, deleting is the ONLY way to stop a step being sent. Keep its content as ' +
      'prose in the flow description if you still need the record.',
    next: 'get_auth_flow_steps',
    derived: true,
  },

  replay_auth_flow_step: {
    step: S_CRAWL,
    tool: 'Re-sends one step at the live target and re-records its response, seeding cookies from ' +
      'the earlier steps.',
    lies: 'No exclusion row and no scope rule applies to this path: grep authFlowsUtils.go and ' +
      'every boundary check returns zero hits. A step whose Host is out of scope goes there.',
    next: 'get_auth_flow_steps, or check_session_tokens action:"validate"',
    derived: false,
  },

  replay_auth_flow: {
    step: S_CRAWL,
    tool: 'Runs an entire flow end to end with one shared cookie jar and re-records every step ' +
      'response. This is how a session is re-established after a token expires.',
    lies: 'It is all or nothing and completely unguarded: no scope check, no exclusion list, no way ' +
      'to disable one step. A "DO NOT REPLAY" in the flow name stops nothing, and a loop of replays ' +
      'is a loop of full login sequences that can trip lockout.',
    next: 'manage_session_tokens action:"parse", then check_session_tokens action:"validate"',
    derived: false,
  },

  // === requestflows.js ==========================================================================

  replay_request: {
    step: S_SCANNING,
    tool: 'The repeater. Search the manual-crawl capture corpus, pull one capture out as raw HTTP ' +
      'bytes, edit them and send them at the live target. It also indexes what the twelve scanner ' +
      'sections found and turns one finding into pasteable bytes.',
    vuln: 'This is where a scanner claim becomes a confirmed finding or dies. Loading and sending ' +
      'are two separate calls on purpose, because a scanner finding is a claim and the send is how ' +
      'you check it.',
    lies: 'q is a GRAMMAR, not a substring: a bare phrase runs a substring hunt across url, method ' +
      'and status and usually returns nothing, which looks exactly like an empty corpus. Call ' +
      'query_syntax before writing a search.',
    next: 'manage_request_versions action:"create", or manage_threat_model action:"create"',
    learn: 'kb://methodology/web-app-methodology',
    derived: false,
    actions: {
      query_syntax: {
        tool: 'Returns the search grammar, its fields and its operators with no round trip. The ' +
          'right first call of any repeater session.',
        next: 'replay_request action:"search_captures"',
      },
      search_captures: {
        tool: 'Finds requests in this target capture corpus using the query language. One row per ' +
          'capture with its id, no bodies.',
        lies: 'An empty result and a broken query look identical, so a mistyped field comes back as ' +
          'a 400 carrying the offset rather than as an empty list. The list caps at 50 rows by ' +
          'default and says when it capped: a truncated list read as the whole corpus is the same ' +
          'mistake one level up.',
        next: 'replay_request action:"get_capture"',
      },
      get_capture: {
        tool: 'One capture as raw HTTP bytes plus the response it originally got. The raw_request ' +
          'it returns is what you edit and hand to send.',
        lies: 'Request bytes are budgeted far higher than response bodies because half a request is ' +
          'not a request, but they can still clip; anything clipped is flagged, and sending clipped ' +
          'bytes sends garbage.',
        next: 'replay_request action:"send"',
      },
      send: {
        tool: 'Puts a real request on the wire at a live host and returns what came back. Nothing ' +
          'is recorded and nothing is stored.',
        lies: 'Because nothing is stored, a result you do not save is gone: use ' +
          'manage_request_versions to keep the edit. This is somebody production host, so read the ' +
          'bytes you are about to send rather than the description of them.',
        next: 'manage_request_versions action:"create"',
      },
      list_findings: {
        tool: 'A cheap index of what the twelve scanner sections found on this target: one short ' +
          'row per finding with its finding_id, its section and tool, and whether it has request ' +
          'bytes worth loading.',
        lies: 'A full results read is around 50kB of prose per tool, which is why this exists. A ' +
          'finding with no loadable bytes is not a weaker finding, it is one whose tool never ' +
          'recorded the request.',
        next: 'replay_request action:"load_finding"',
      },
      load_finding: {
        tool: 'Turns ONE finding into raw bytes you can hand straight to send, plus the base_url to ' +
          'aim them at. It sends nothing.',
        lies: 'Composed request bytes are stored behind a banner that is not valid HTTP; this ' +
          'strips it and tells you it was there. Read raw_request_origin before quoting the result ' +
          'anywhere, because "reconstructed" and "captured" are different claims about the same ' +
          'field.',
        next: 'replay_request action:"send"',
      },
    },
  },

  manage_request_versions: {
    step: S_SCANNING,
    tool: 'Version history for a replayed request. Nothing is ever overwritten: the capture ' +
      'unmodified bytes are the ORIGINAL and every edit is a new row remembering what it descended ' +
      'from, so there is always a way back to what the target actually said.',
    lies: 'Passing capture_id to list also MATERIALISES the original if it does not exist yet. ' +
      'There is no separate "start versioning" call, so an empty history on a capture you never ' +
      'listed is expected rather than informative.',
    next: 'replay_request action:"send", or manage_flow_builder action:"add_step"',
    derived: false,
    actions: {
      get: {
        tool: 'One version with its full bytes. Needs target_id as well as version_id, because no ' +
          'route fetches a version by id alone and it is resolved through the target list.',
        next: 'manage_request_versions action:"send"',
      },
      create: {
        tool: 'Saves an edit as a NEW version descending from the one it was made from. Both ' +
          'remain.',
        lies: 'parent_version_id defaults to the capture ORIGINAL when capture_id is given, which ' +
          'is what makes the first edit produce a real diff label. Omit both and the label ' +
          'describes a diff against nothing.',
        next: 'manage_request_versions action:"send"',
      },
      update: {
        tool: 'Changes a version bytes, base URL or label in place.',
        lies: 'The ORIGINAL is immutable and refuses update and delete, because being able to get ' +
          'back to what the target actually said is the entire point of the feature. Edit it by ' +
          'saving a new version instead.',
        next: 'manage_request_versions action:"list"',
      },
      delete: {
        tool: 'Removes one edit. Its children are reparented onto its own parent so the history ' +
          'stays connected and you lose only the step you asked to lose.',
        next: 'manage_request_versions action:"list"',
      },
      send: {
        tool: 'Puts the stored bytes on the wire at a live host and returns what came back. Sending ' +
          'never modifies the version, including the original.',
        lies: 'A version that sends successfully today proves nothing about the bytes stored ' +
          'yesterday under a different session; the request is replayed verbatim, expired tokens ' +
          'and all.',
        next: 'manage_threat_model action:"create"',
      },
    },
  },

  manage_detected_flows: {
    step: S_BYPASS,
    tool: 'Every flow on a target, of BOTH kinds: the ones reconstructed from the capture corpus (a ' +
      'form POST and the page its 302 produced, an OAuth dance across three hosts) and the ones an ' +
      'operator assembled in the flow builder. List, read one as a graph, name it, and re-run it at ' +
      'the live target.',
    vuln: 'A flow is the unit of every access control and business logic test, because those bugs ' +
      'live in a sequence rather than in a single request.',
    lies: 'THE TWO KINDS HAVE DIFFERENT ID SHAPES and only name accepts both: a detected flow id is ' +
      '<session>~<tab>~<root capture> and is NOT a UUID, a built flow id is. Built flows are never ' +
      'filtered by the query, because the grammar matches captured requests and a built flow holds ' +
      'steps that may never have been sent.',
    next: 'manage_flow_builder action:"seed_from_detected_flow", or manage_threat_model ' +
      'action:"link_flow"',
    derived: false,
    actions: {
      list: {
        tool: 'Every flow of both kinds, built ones first, each row carrying kind and the flow_id ' +
          'the other actions take. built_count says how many of the rows they are.',
        lies: 'An unnamed flow shows a DERIVED label taken from the request that rooted it, and a ' +
          'browsing session roots most of its flows at the same handful of navigations, so forty ' +
          'flows can show six distinct labels. Name the ones worth returning to.',
        next: 'manage_detected_flows action:"get" or action:"name"',
      },
      get: {
        tool: 'One DETECTED flow as a graph: nodes are requests and edges carry the REASON they ' +
          'were drawn.',
        lies: 'A built flow id is refused here; read one with manage_flow_builder action:"get_flow" ' +
          'instead. The graph is derived fresh on every request, so it reflects the capture corpus ' +
          'as it stands now and not as it stood when you last looked.',
        next: 'manage_flow_builder action:"seed_from_detected_flow"',
      },
      name: {
        tool: 'Gives the flow a name and optionally a description so it can be recognised later. ' +
          'For a detected flow the name is the one thing about it that is actually stored.',
        lies: 'name and description are independent HERE only because this tool makes them so: the ' +
          'underlying PUT reads both as pointers, so a hand-rolled call sending a name alongside an ' +
          'empty description string blanks prose somebody wrote. A blank name is refused rather ' +
          'than treated as a clear.',
        next: 'manage_detected_flows action:"list"',
      },
      run: {
        tool: 'Sends the whole flow again, request by request, at the live target. It is a DRY RUN ' +
          'unless you pass dry_run:false.',
        lies: 'The dry run is the right first call every time: it returns the exact bytes of every ' +
          'step, how many requests would go out, to which hosts, how many carry your recorded ' +
          'session, and what the engagement rules will change on the way out. A live run replays ' +
          'whatever verbs the flow captured, including writes.',
        next: 'manage_detected_flows action:"run_status"',
      },
      cancel_run: {
        tool: 'Stops a run in flight. Everything it already sent is kept.',
        next: 'manage_detected_flows action:"run_status"',
      },
    },
  },

  // === flowdetection.js =========================================================================

  manage_flow_detection: {
    step: S_BYPASS,
    tool: 'Plans and runs ACTIVE flow detection against a target, and manages the endpoints it must ' +
      'never touch. Detection sends real requests to discover which endpoints chain into flows.',
    vuln: 'Not a vulnerability scan. It builds the sequence corpus that access control and business ' +
      'logic testing then works from.',
    lies: 'dry_run sends nothing and returns the exact request list plus every endpoint it would ' +
      'skip with the rule that skipped it, so there is no reason to ever run blind. An exclusion ' +
      'has no method parameter, so it cannot block a DELETE without also killing the GET on the ' +
      'same path, which is why per-endpoint deselection is load-bearing here.',
    next: 'manage_flow_config action:"endpoint_summary", then manage_detected_flows action:"list"',
    derived: false,
    actions: {
      dry_run: {
        tool: 'Plans a run and sends nothing: the exact requests it would make, every skip with its ' +
          'reason, and the config after the target engagement rules were folded in. Free, so do it ' +
          'first.',
        lies: 'Read the plan for write verbs. Endpoint selection DEFAULTS TO SELECTED, so anything ' +
          'that grows the candidate corpus makes its write endpoints instantly sendable: one fix to ' +
          'the candidate loader took a target from 0 to 202 endpoints and made 14 writes sendable ' +
          'at once, including two DELETEs and a trade-placing POST.',
        next: 'manage_flow_config action:"deselect", then manage_flow_detection action:"run"',
      },
      run: {
        tool: 'Executes the plan against the live target. This puts real requests on a real bug ' +
          'bounty programme.',
        lies: 'A deselection only covers the endpoints that existed when it was made. After any new ' +
          'crawl, consolidation, import or loader change, re-check that state=sendable contains ' +
          'zero POST, PUT, PATCH or DELETE before running.',
        next: 'manage_flow_detection action:"status"',
      },
      cancel: {
        tool: 'Stops the run in progress. It stops after the request in flight and KEEPS every ' +
          'capture it already wrote, so the flows it found survive.',
        next: 'manage_flow_detection action:"status"',
      },
      add_exclusion: {
        tool: 'Adds a never-send-here rule. Both a pattern and a reason are required, and the API ' +
          'refuses a blank reason rather than defaulting it.',
        lies: 'Exclusions constrain ACTIVE FLOW DETECTION ONLY. replay_auth_flow, ' +
          'replay_auth_flow_step and the repeater ignore them entirely, so an exclusion is not a ' +
          'safety boundary for the engagement, only for this one runner.',
        next: 'manage_flow_detection action:"dry_run"',
      },
      list_exclusions: {
        tool: 'The operator rules that say never send here, each with the reason somebody wrote for ' +
          'it.',
        lies: 'An exclusion with no reason is one the next operator deletes because nothing tells ' +
          'them what it was protecting. On one target in this database six endpoints text a real ' +
          'customer when hit.',
        next: 'manage_flow_detection action:"dry_run"',
      },
    },
  },

  manage_flow_config: {
    step: S_BYPASS,
    tool: 'Which endpoints detection may reach, and the per-target programme requirements ' +
      '(mandatory header, User-Agent, rate cap, timeout, redirect depth) with per-field provenance ' +
      'saying whether each value was set here, inherited from the global settings, or is a built-in ' +
      'default.',
    lies: 'Endpoints default to SELECTED, so a growing corpus silently arms new write endpoints. ' +
      'sendable is the number that matters: on one live target total was 1,872 and sendable was 22, ' +
      'because the other 1,850 sat on hosts outside the boundary.',
    next: 'manage_flow_detection action:"dry_run"',
    derived: false,
    actions: {
      endpoint_summary: {
        tool: 'The partition alone: total, selected, deselected, excluded, out_of_scope and ' +
          'sendable, with no rows. Cheap, so use it to decide whether listing is worth it.',
        lies: 'A large total with a tiny sendable count is usually a scope boundary doing its job, ' +
          'not a detection failure. Check manage_scope_rules before widening anything.',
        next: 'manage_flow_config action:"list_endpoints" with state:"sendable"',
      },
      list_endpoints: {
        tool: 'Every endpoint detection could reach with why each one would or would not be sent ' +
          'to. Thousands of rows on a real target, so filter.',
        lies: 'q here is a plain case-insensitive substring over method, host, path and URL, NOT ' +
          'the capture query language the repeater uses. Expect truncation and read the cap rather ' +
          'than assuming the list is complete.',
        next: 'manage_flow_config action:"deselect"',
      },
      deselect: {
        tool: 'Bulk turns endpoints off by endpoint_keys, or all:true for every endpoint that ' +
          'exists right now.',
        lies: 'all:true covers what exists AT THAT MOMENT. Anything added later comes back selected ' +
          'by default, so this has to be re-run after any crawl, consolidation or import.',
        next: 'manage_flow_detection action:"dry_run"',
      },
      set_engagement: {
        tool: 'Sets one or more programme requirement fields. A field you do not mention is left ' +
          'alone.',
        lies: 'Sending an empty string does not clear a field; clear_engagement_field is the only ' +
          'way to drop an override and fall back to the global or the built-in default.',
        next: 'manage_flow_config action:"get_engagement"',
      },
      get_engagement: {
        tool: 'This target programme requirements with per-field provenance saying whether each ' +
          'value was set on the target, inherited from the global settings, or is a built-in ' +
          'default.',
        lies: 'A correct-looking rate cap that came from a built-in default is not a value anybody ' +
          'chose for this programme. Read the provenance, not just the number.',
        next: 'manage_flow_config action:"set_engagement"',
      },
    },
  },

  get_flow_metrics: {
    step: S_BYPASS,
    tool: 'The four numbers above the Request Flow Replay buttons: sendable endpoints of everything ' +
      'discovered, detected flows, built flows and saved repeater versions.',
    lies: 'A number that could not be read is reported as UNAVAILABLE, never as zero, because this ' +
      'estate has repeatedly shipped fields named like a corpus total that were really an artefact ' +
      'of the query. Treat unavailable as "go look", not as "none".',
    next: 'manage_flow_config action:"endpoint_summary", or manage_detected_flows action:"list"',
    derived: false,
  },

  // === flowbuilder.js ===========================================================================

  manage_flow_builder: {
    step: S_BYPASS,
    tool: 'Builds, edits and runs multi-step request flows: an ordered list of raw HTTP requests ' +
      'with values carried from one step into the next and conditions that branch on what the ' +
      'target answers. It is the only way to test a SEQUENCE rather than a request.',
    vuln: 'This is the shape almost every access control and business logic test actually takes: ' +
      'log in as A, create an object, then try to read it as B. Those bugs have no scanner ' +
      'signature because a successful attack returns an ordinary 200.',
    lies: 'A flow that ran is not a flow that is proven: a run whose steps were edited afterwards ' +
      'reads as stale, and verified means the map is current rather than that the flow PASSED. Both ' +
      'flows on one reference target were verified while having failed at step one on an expired ' +
      'bearer token.',
    next: 'manage_threat_model action:"link_flow", or replay_request action:"send"',
    learn: 'kb://methodology/vulnerability-chaining',
    derived: false,
    actions: {
      grammar: {
        tool: 'The condition grammar, the actions, the save-time rules, worked examples, and every ' +
          'loop-protection cap with its default and ceiling. Takes no arguments.',
        lies: 'Read this BEFORE writing any condition or retry loop. A condition that does not ' +
          'parse is refused at save time, but one that parses and targets the wrong field runs ' +
          'happily and branches the wrong way.',
        next: 'manage_flow_builder action:"seed_from_detected_flow"',
      },
      seed_from_detected_flow: {
        tool: 'THE PATH MOST OPERATORS WANT: take a flow the detector already found, turn its ' +
          'captured requests into editable steps in flow order, then change the one step you care ' +
          'about. Detect, then change.',
        lies: 'The seeded steps arrive ENABLED whatever verb they carry, so a seeded flow can be ' +
          'one replay away from re-sending a POST or a DELETE the crawl happened to capture. Scope ' +
          'and the exclusion rules still decide what may go out, but neither of those knows about ' +
          'verbs.',
        next: 'manage_flow_builder action:"preview"',
      },
      seed_from_captures: {
        tool: 'The same thing from an explicit list of capture ids, for a flow the detector did not ' +
          'segment the way you want.',
        lies: 'The steps are ordered by WHEN THEY WERE RECORDED, not by the order you listed them, ' +
          'so a deliberate reordering has to be done afterwards with reorder_steps or move_step.',
        next: 'manage_flow_builder action:"reorder_steps"',
      },
      get_flow: {
        tool: 'One flow with its steps (raw requests clipped), the dry-run preview of what a replay ' +
          'would send, the scope boundary those steps are judged against, the caps a run would be ' +
          'held to, and any cycle warnings. This is the main read.',
        lies: 'The raw requests here are CLIPPED. Use get_step for the whole bytes of one step ' +
          'before quoting or re-typing a request.',
        next: 'manage_flow_builder action:"preview"',
      },
      create_flow: {
        tool: 'An empty flow. Usually the wrong start: prefer seed_from_detected_flow so the steps ' +
          'come from bytes the target actually accepted.',
        next: 'manage_flow_builder action:"add_step"',
      },
      add_step: {
        tool: 'Appends a step, either from raw_request bytes you write or from capture_id which ' +
          'rebuilds a recorded request. Never sent on add.',
        lies: 'A step name is what goto and step.<name> conditions refer to, so keep it short, ' +
          'unique within the flow and stable once a condition points at it. Renaming a referenced ' +
          'step breaks the branch that pointed at it.',
        next: 'manage_flow_builder action:"preview"',
      },
      update_step: {
        tool: 'Edits a step. Every field is optional and an omitted one is left alone, and this is ' +
          'also how you turn a step off with enabled:false or back on.',
        lies: 'extractions:[] and conditions:[] CLEAR those lists rather than leaving them alone, ' +
          'which is the one place the omitted-is-untouched rule does not hold.',
        next: 'manage_flow_builder action:"preview"',
      },
      preview: {
        tool: 'The dry run: which steps would go out, to which hosts, with which verbs, which would ' +
          'be refused and why, and how many requests that is. SENDS NOTHING.',
        lies: 'Do this before every replay, not just the first. A step edited since the last preview ' +
          'can change the host, the verb or the branch taken, and the preview is the only place ' +
          'that is visible before the packets leave.',
        next: 'manage_flow_builder action:"replay"',
      },
      replay: {
        tool: 'Runs the flow: live requests, conditions followed, and an execution trace with the ' +
          'outcome and the caps it was judged against.',
        lies: 'The outcome is whether the run completed, not whether the test succeeded. Keep ' +
          'last_run_outcome separate from the verification state, because a verified flow can have ' +
          'failed at step one.',
        next: 'manage_threat_model action:"link_flow"',
      },
      replay_step: {
        tool: 'Re-sends ONE step, seeding cookies and captured values from responses earlier steps ' +
          'have ALREADY recorded rather than by re-sending them. This is how you iterate on step ' +
          'four without firing the whole flow each time.',
        lies: 'It uses recorded values, so a captured token that has since expired is replayed as ' +
          'if it were live and the step fails for a reason that has nothing to do with the change ' +
          'you made. A turned-off step is refused.',
        next: 'manage_flow_builder action:"replay"',
      },
      get_step: {
        tool: 'One step in full: the whole raw request, all its captures, all its conditions and ' +
          'its stored response.',
        lies: 'There is no route for this, so it reads the flow and picks the step out. Pass ' +
          'flow_id or it has to ask every flow on the target one at a time.',
        next: 'manage_flow_builder action:"update_step"',
      },
      delete_flow: {
        tool: 'Removes the flow and its steps. No restore.',
        lies: 'Any threat linked to it keeps the link, because the flow side is not a foreign key; ' +
          'the threat simply loses its evidence and the link reads as unresolved.',
        next: 'manage_threat_model action:"list_flow_links"',
      },
    },
  },
};
