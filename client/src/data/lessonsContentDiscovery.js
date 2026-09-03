// Content discovery: fuzzing for what nothing links to.
//
// This file exists because of a specific, expensive omission. On the first full engagement with this
// framework the fuzzing flow was built as ten steps, and every one of them fuzzed query parameters,
// headers or cookies against endpoints that were ALREADY KNOWN. Not one step put FUZZ in the path.
// Content discovery at the web root, which is the first command of any engagement, never ran. As a
// direct result /admin was never requested, never returned its 403, never entered any table, and the
// entire access-bypass section had nothing to work on, on a target where an unauthenticated header
// bypass of the admin panel was real and was eventually found by hand.
//
// The capability was never missing. ffuf-wordlist-5000.txt ships with the framework and its fourth
// line is literally "admin".

export const contentDiscoveryLessons = {
  urlContentDiscoveryMethodology: {
    title: "Content Discovery: The First Command of the Engagement",
    overview: "Crawling finds what an application advertises. Archives find what it used to advertise. Neither finds the thing nobody links to, and the thing nobody links to is usually the least protected thing on the target. Fuzzing the web root for hidden paths is day one of bug bounty hunting and it belongs before anything clever.",
    sections: [
      {
        title: "Why It Goes First",
        icon: "fa-flag",
        content: [
          "Every later step is bounded by the endpoint list. Parameter enumeration finds hidden inputs on endpoints you already have. The access-control sections need endpoints that already returned a 401 or a 403. The vulnerability scanners run against attack vectors, and vectors are built from endpoints. If the endpoint list is missing the admin panel, then nothing downstream can find it, and every section will report clean while being entirely correct.",
          "This is not a hypothetical ordering argument. On the reference engagement the fuzzing phase ran ten steps against parameters, headers and cookies, and the access bypass section ended with zero targets because there were no 401 or 403 responses anywhere in the database. Nothing had ever requested a path that returns one.",
          "The cost of getting the order wrong is invisible, which is what makes it worth stating plainly. A section with no targets does not error. It completes, reports nothing, and looks exactly like a section that found nothing to report."
        ],
        keyPoints: [
          "Fuzz the web root before parameters, before headers, before anything else",
          "Every later step is bounded by the endpoint list this step produces",
          "A section with no targets reports clean rather than failing",
          "The least advertised resources are usually the least protected"
        ]
      },
      {
        title: "What You Are Looking For",
        icon: "fa-box-open",
        content: [
          "Administrative interfaces, staging and development routes, old API versions still deployed, backup and archive files, configuration left in the web root, debug endpoints, and anything whose name suggests it was never meant for the public.",
          "Treat 401 and 403 as findings rather than as noise. A 403 means the resource exists and is being withheld, which is both a disclosure of the application's structure and the single best input to an access-control bypass attempt. Most people filter these out along with the 404s, which throws away the most interesting results in the run.",
          "A 301 or 302 is worth reading too: the destination tells you about routing you had not seen, and a redirect to a login page is a strong hint that something authenticated lives there."
        ],
        keyPoints: [
          "Admin panels, staging routes, old API versions, backups, config, debug endpoints",
          "401 and 403 are findings, not noise: the resource exists and is being withheld",
          "Redirect destinations reveal routing you have not mapped",
          "Anything that looks forgotten is worth more than anything that looks maintained"
        ]
      }
    ],
    practicalTips: [
      "Run it at the web root first, then again under every directory prefix you discover",
      "Run it again later: a path learned from a JavaScript file suggests siblings worth trying",
      "Record the 401s and 403s deliberately; they are the input to the bypass section",
      "Re-run content discovery on every host, not only the apex",
      "Fuzzing parameters before discovering endpoints is doing step four before step one"
    ],
    furtherReading: [
      {
        title: "SecLists - Web Content Discovery",
        url: "https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content",
        description: "The standard wordlists, with the raft and quickhits families"
      },
      {
        title: "OWASP WSTG - Review Old Backup and Unreferenced Files",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
        description: "The methodical version of what this automates"
      }
    ]
  },

  urlContentDiscoveryFfuf: {
    title: "Driving FFUF Well",
    overview: "FFUF sends one request per wordlist entry and shows you which ones came back interesting. Everything that separates a useful run from a wall of noise is in how you decide what interesting means, and that decision has to be made against the target's own baseline rather than from a template.",
    sections: [
      {
        title: "Baseline First, Filters Second, Volume Last",
        icon: "fa-sliders",
        content: [
          "Before sending tens of thousands of requests, learn what a definitely-missing path looks like on this target. Request something that certainly does not exist and read the response. If a miss returns a 404, matching on status is enough. If a miss returns a 200 carrying a themed not-found page, status matching finds everything and tells you nothing, and you have to filter on size, word count or line count instead.",
          "That is what the filter flags are for. Use -fc to drop status codes, -fs to drop a response size, -fw to drop a word count and -fl to drop a line count. Filtering on size or words is usually more effective than status on a modern application, because the interesting difference is in the body rather than the code.",
          "Then scale up. Start with a small curated list to set the filters, then run a larger one once they are right. Running the largest list first means discovering your filters were wrong after a hundred thousand requests rather than after two hundred."
        ],
        keyPoints: [
          "Measure the not-found response before choosing how to filter",
          "-fc status, -fs size, -fw words, -fl lines",
          "On modern apps, size and word filters beat status filters",
          "Small list to tune, large list to cover"
        ],
        examples: [
          {
            code: "ffuf -u https://target/FUZZ -w common.txt -mc all",
            description: "First pass: match everything and look at the shape of the results"
          },
          {
            code: "ffuf -u https://target/FUZZ -w raft-medium-directories.txt -fs 1024",
            description: "Second pass: the 1024-byte not-found page filtered out by size"
          }
        ]
      },
      {
        title: "Auto-Calibration, and When It Lies",
        icon: "fa-scale-balanced",
        content: [
          "The -ac flag makes FFUF send a handful of deliberately random paths first, measure what the target returns for them, and filter anything matching that shape. It is the fastest way to get a clean result on a target with a soft not-found page, and it is the right default.",
          "It is also capable of hiding real findings. Auto-calibration suppresses responses that RESEMBLE the baseline, so on an application whose genuine content resembles its own not-found page, real results get filtered away silently. This has been measured on this framework in the opposite direction too: turning calibration off on one bypass tool took a clean report to three bypasses that did not exist.",
          "The habit worth building is to run once with calibration and once without on anything important, and to compare the counts. A large difference is telling you something about the target's response shapes that you want to know."
        ],
        keyPoints: [
          "-ac calibrates against random paths and filters what matches",
          "It is the right default on a target with a soft 404",
          "It can silently drop real findings that resemble the baseline",
          "Compare a calibrated and an uncalibrated run on anything that matters"
        ]
      },
      {
        title: "Extensions, Recursion and Pacing",
        icon: "fa-layer-group",
        content: [
          "Once you know the stack, fuzz for its file types. The -e flag appends extensions to every word, so -e .php,.bak,.old,.zip,.sql,.json turns a directory list into a hunt for backups and configuration. Backup files are among the highest-value results in content discovery because they are frequently readable and frequently contain credentials.",
          "Recursion turns a discovered directory into a new starting point automatically. Use -recursion with -recursion-depth to bound it: unbounded recursion on a large wordlist multiplies your request count by the number of directories you find, which is how a considerate scan becomes a denial of service by accident.",
          "Pace it deliberately. Use -rate to cap requests per second and -p to add a delay between them. On a production target, tuning the flags is worth far more than raw thread count: a fast scan that gets you blocked returns nothing, and a blocked IP ends the engagement. If the framework has measured a safe rate for this target, use that number rather than a default."
        ],
        keyPoints: [
          "-e appends extensions; backups and config are the high-value hits",
          "-recursion with -recursion-depth, always bounded",
          "-rate and -p to stay within what the target tolerates",
          "Tuning beats threads on anything in production"
        ],
        examples: [
          {
            code: "ffuf -u https://target/FUZZ -w raft-medium-directories.txt -recursion -recursion-depth 2 -rate 5",
            description: "Recursive directory discovery, bounded, paced at a measured safe rate"
          },
          {
            code: "ffuf -u https://target/FUZZ -w files.txt -e .bak,.old,.zip,.sql,.json -fc 404",
            description: "Backup and configuration hunt over a known directory"
          }
        ]
      }
    ],
    practicalTips: [
      "Measure the not-found response before you choose a filter",
      "Tune on a small list, then scale to raft-medium and raft-large",
      "Keep 401 and 403 in your results deliberately; they feed the bypass section",
      "Bound recursion depth, always",
      "Use the rate the target probe measured rather than a default",
      "Fuzz extensions as a separate run: mixed baselines ruin the filters for both"
    ],
    furtherReading: [
      {
        title: "Everything you need to know about FFUF - Codingo",
        url: "https://codingo.com/posts/2020-08-29-everything-you-need-to-know-about-ffuf/",
        description: "Calibration, filtering and pacing, from the tool's own community"
      },
      {
        title: "ffuf",
        url: "https://github.com/ffuf/ffuf",
        description: "The flag reference"
      }
    ]
  },

  urlContentDiscoveryWordlists: {
    title: "Choosing a Wordlist",
    overview: "Wordlist choice decides what a content discovery run can possibly find, and a bigger list is not automatically a better one. A list matched to the target finds more with fewer requests than a generic million-line list, and it finishes in time to act on.",
    sections: [
      {
        title: "Start Small, Then Go Wide",
        icon: "fa-list-ol",
        content: [
          "Begin with a small curated list such as common.txt or quickhits.txt. Two hundred to a few thousand entries is enough to learn the target's response shapes, set the filters correctly, and catch the obvious wins, which are more common than people expect.",
          "Then move to the raft family: raft-medium-directories and raft-medium-files at roughly thirty and seventeen thousand entries are the standard working lists, and raft-large or directory-list-2.3-big when a target justifies the time. These are ordered by observed frequency, so the useful results tend to arrive early even if you stop the run.",
          "Consolidated lists exist that merge many sources and deduplicate them, which trades precision for coverage. They are a reasonable single choice when you have no information about the stack, and a poor one once you do."
        ],
        keyPoints: [
          "common.txt or quickhits.txt to tune filters and catch the easy wins",
          "raft-medium-directories and raft-medium-files as the working default",
          "raft-large or a big directory list when the target justifies it",
          "Frequency-ordered lists deliver their value early"
        ]
      },
      {
        title: "Tailor It to What You Know",
        icon: "fa-crosshairs",
        content: [
          "Once you know the technology, use a list built for it. A PHP application wants .php extensions and PHP-specific paths; a Java application wants a different set entirely; an API wants API-shaped route names rather than website directory names. The same request budget spent on a matched list finds substantially more.",
          "Build target-specific lists as you go. Words from the application's own pages, its JavaScript, its error messages and its naming conventions make an excellent custom list, because internal naming is consistent and rarely appears in any public wordlist.",
          "Keep the framework's uploaded wordlists purposeful. A list you assembled for a previous target is usually the wrong list for this one, and a stale list quietly costs you both time and coverage."
        ],
        keyPoints: [
          "Match the list to the stack once the stack is known",
          "Harvest words from the application's own text and scripts",
          "Internal naming conventions are consistent and never in public lists",
          "A previous target's list is rarely the right one for this target"
        ]
      }
    ],
    practicalTips: [
      "Small list first, always, to set the filters",
      "Add extensions matched to the stack rather than fuzzing every extension",
      "Build a custom list from the target's own vocabulary",
      "Prefer a matched list over a bigger list when you have to choose",
      "Delete stale uploaded lists; they cost coverage without anyone noticing"
    ],
    furtherReading: [
      {
        title: "SecLists Discovery - Web Content",
        url: "https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content",
        description: "The raft, common and quickhits families"
      }
    ]
  }
};
