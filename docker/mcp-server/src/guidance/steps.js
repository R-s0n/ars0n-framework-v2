// The step vocabulary, named once for all four domain files.
//
// WHY THIS FILE EXISTS. recon.js and data.js each declared their own S_CRAWL, S_ARCHIVE and
// S_CONSOLIDATE, and they disagreed: the same three methodology steps were shipping as "1/8 Manual
// crawling" and "1/8 Manual Crawl", "3/8 Archive and JavaScript mining" and "3/8 Archive Discovery",
// "5/8 Consolidate attack vectors" and "5/8 Consolidate Vectors". scanning.js and workflow.js then
// wrote a third spelling inline, "Recon pillar, before 1/8 Manual Crawling" against recon.js's
// "Recon (before 1/8 Manual crawling)".
//
// That is not cosmetic. `step` is the field that tells an agent WHERE IT IS, and two names for one
// place is two places: a caller that has been told manage_param_enum is "4/8 Hidden parameter
// enumeration" and query_parameters is "4/8 Parameter Discovery" has been told they are different
// phases of the workflow, which is the exact confusion this whole layer exists to remove.
// assemble() in index.js already refuses to let two domain files claim one TOOL; nothing was
// stopping them claiming one STEP under two names, so the labels moved here and a test now refuses
// any step value that is not one of them.
//
// The eight numbered steps are server/utils/methodology.go, in its order. They are ABBREVIATED, not
// verbatim: that file titles step 2 "Content discovery: fuzzing for hidden paths" and step 6
// "Running the vulnerability scanners", which are sentences rather than labels, and this string is
// prefixed to a reminder line that has a character budget. The number carries the identity, so
// "6/8" cannot be mistaken for a different step from get_methodology's sixth whatever it is called.
//
// Three labels are deliberately NOT numbered. The Wildcard and Company workflows run before step
// one, the Target Behaviour Probe runs before them, and configuration applies to all of it; giving
// any of them a step number would invent a step get_methodology would then contradict.

const PRE = 'Recon (before 1/8 Manual Crawl)';
const PROBE = '0/8 Target Behaviour Probe, before 1/8 Manual Crawl';
const CRAWL = '1/8 Manual Crawl';
const CONTENT = '2/8 Content Discovery';
const ARCHIVE = '3/8 Archive Discovery';
const PARAMS = '4/8 Parameter Discovery';
const CONSOLIDATE = '5/8 Consolidate Vectors';
const SCANNING = '6/8 Vector Scanning';
const BYPASS = '7/8 Access Bypass';
const THREAT = '8/8 Threat Model';
const ANY = 'Any step';
const CONFIG = 'Configuration, applies to every step';

// A few tools genuinely straddle steps or sit beside one, and saying so is more useful than picking
// the nearest. Composed from the constants above rather than written out, so renaming a step renames
// it everywhere including here.
const SCANNING_ANY_TABLE = `${SCANNING}, though it reads any step's scanner table`;
const SCANNING_BEFORE_CHOOSING = `${SCANNING}, read before choosing scanners`;
const CONTENT_TO_PARAMS = `${CONTENT} through ${PARAMS}`;
const PRE_PLUS_ARCHIVE_PARAMS = `Recon, plus ${ARCHIVE} and ${PARAMS}`;

const STEPS = {
  PRE,
  PROBE,
  CRAWL,
  CONTENT,
  ARCHIVE,
  PARAMS,
  CONSOLIDATE,
  SCANNING,
  BYPASS,
  THREAT,
  ANY,
  CONFIG,
  SCANNING_ANY_TABLE,
  SCANNING_BEFORE_CHOOSING,
  CONTENT_TO_PARAMS,
  PRE_PLUS_ARCHIVE_PARAMS,
};

// Every value any entry is allowed to carry in `step`. The test that enforces this is the point of
// the file: without it the next domain file added would spell a step whatever its author remembered.
const ALLOWED_STEPS = new Set(Object.values(STEPS));

module.exports = { ...STEPS, STEPS, ALLOWED_STEPS };
