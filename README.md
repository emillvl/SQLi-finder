# SQLi-Finder

A small, conservative SQL injection indicator checker for **authorized HTTP(S) targets**.

You supply the URLs you are allowed to test. SQLi-Finder checks their query-string parameters for error-based SQL injection indicators. It does not discover arbitrary websites through search-engine dorks, does not bypass bot detection, and does not attempt exploitation or data extraction.

## Background

The original version of this project automated Google dork searches, used `undetected_chromedriver`, and treated large page differences as evidence of SQL injection.

That approach had two problems:

1. it encouraged broad public-web scanning rather than explicit-scope testing;
2. dynamic pages can change between requests, so page-source differences alone produce noisy false positives.

The current tool uses an explicit target list and compares database-error signatures alongside response behavior.

## Features

- tests only URLs supplied by the user;
- requires an explicit `--authorized` confirmation;
- supports one URL or a text file containing multiple targets;
- tests query parameters one at a time;
- uses a single-quote mutation for conservative error-based checks;
- compares baseline and probe responses;
- recognizes common MySQL, PostgreSQL, SQL Server, Oracle, SQLite, and ODBC error signatures;
- reports `likely`, `possible`, `not_detected`, `skipped`, or `error`;
- rate-limits requests with a configurable delay;
- uses request timeouts;
- disables automatic redirects while probing;
- caps response bodies to reduce unnecessary memory use;
- writes machine-readable JSON Lines output.

## Interpreting findings

SQLi-Finder reports indicators that need manual verification.

A `likely` result means a new database error signature appeared after a parameter was modified. A `possible` result means the request caused a strong server-side behavior change, such as a new 5xx response plus a substantial body-size change.

Neither result should be treated as a complete vulnerability assessment on its own.

The tool does not perform:

- authentication bypass;
- UNION-based extraction;
- blind boolean inference;
- time-delay payloads;
- schema enumeration;
- data extraction;
- stacked-query testing;
- POST-body fuzzing;
- cookie/header fuzzing.

If you need a complete assessment, validate the finding manually in a controlled environment and use established security-testing tooling under authorization.

## Requirements

- Python 3.10+
- `requests`

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

### Test one authorized URL

```bash
python sqli_finder.py \
  --authorized \
  --url "https://example.test/product.php?id=5"
```

### Test several URLs

Repeat `--url`:

```bash
python sqli_finder.py \
  --authorized \
  --url "https://example.test/product.php?id=5" \
  --url "https://example.test/view.php?post=12&lang=en"
```

### Read targets from a file

Create a file such as:

```text
https://example.test/product.php?id=5
https://example.test/view.php?post=12&lang=en
```

Then run:

```bash
python sqli_finder.py --authorized --input targets.txt
```

Blank lines and lines beginning with `#` are ignored.

## Options

```text
--url URL          Add an authorized target URL. Repeatable.
--input FILE       Read authorized target URLs from a text file.
--authorized       Confirm authorization for all supplied targets.
--timeout SECONDS  Request timeout. Default: 10.
--delay SECONDS    Delay between requests. Default: 0.75.
--output FILE      JSONL output path. Default: sqli_results.jsonl.
--no-output        Do not write a result file.
--version          Print the program version.
```

## Result states

### `likely`

A database error family was absent from the baseline response and appeared only after the parameter probe.

Example evidence:

```text
new database error signature after probe: mysql
```

This is the strongest result the tool emits, but it still warrants manual verification.

### `possible`

The probe caused a significant server-side behavior change, currently requiring both:

- a transition from a non-5xx baseline to a 5xx response; and
- at least a 25% response-size difference.

The result explicitly notes that this is not proof of SQL injection.

### `not_detected`

No configured SQL error signature or strong behavioral indicator was observed.

This does **not** mean the parameter is guaranteed safe. Blind SQL injection, filtered error messages, WAF behavior, or application-specific handling can hide a vulnerability from this detector.

### `skipped`

The supplied URL has no query-string parameter to test.

### `error`

The baseline or probe request failed.

## Output format

By default, each parameter check is appended to `sqli_results.jsonl`.

Example:

```json
{"url":"https://example.test/product.php?id=5","parameter":"id","result":"likely","evidence":["new database error signature after probe: mysql"],"baseline_status":200,"probe_status":500,"baseline_bytes":8421,"probe_bytes":9132}
```

JSON Lines makes the results easy to process with Python, `jq`, or other tooling.

## Detection model

For each supplied URL:

1. SQLi-Finder downloads a baseline response.
2. It identifies query-string parameters.
3. It modifies one parameter at a time by appending a single quote.
4. It downloads the probe response.
5. It compares database-error signatures and basic response behavior.
6. It reports the result without attempting exploitation.

Automatic redirects are disabled so a probe-induced redirect does not silently turn into an unrelated destination response.

Response bodies are limited to 512 KiB because SQL error detection does not require downloading arbitrarily large pages.

## False positives and false negatives

False positives may still occur when:

- the application exposes generic SQL-like text;
- backend failures happen coincidentally during a probe;
- a reverse proxy or error handler changes responses dramatically.

False negatives may occur when:

- SQL errors are suppressed;
- injection is blind;
- the vulnerable input is outside the query string;
- a WAF normalizes or blocks probes;
- the application requires authentication or state;
- the vulnerable request requires POST, JSON, cookies, or custom headers.

Use the results to decide what to investigate. They do not establish whether a target is vulnerable or safe.

## Responsible use

Use SQLi-Finder only on systems you own or systems for which you have explicit permission to perform security testing.

The required `--authorized` flag asks you to confirm permission for every supplied target before testing.

It does not attempt to hide its traffic. The default User-Agent identifies the request as an authorized security test and links back to this project.

## Repository structure

```text
SQLi-finder/
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
├── sqli_finder.py
└── tests/
    └── test_sqli_finder.py
```

## Design choices

### Why no Google dorks?

Discovery and vulnerability verification are separate problems.

Keeping target discovery out of the scanner makes authorization boundaries clearer and removes a dependency on search-engine scraping and anti-bot workarounds.

### Why no browser automation?

This detector does not need a full browser. Direct HTTP requests are easier to audit, faster to run, and introduce fewer moving parts.

### Why not flag every changed page?

Modern pages are dynamic. Ads, timestamps, CSRF values, recommendation modules, rotating content, and analytics data can make two legitimate responses differ substantially.

A changed response alone is therefore not treated as a SQL injection finding.

## Tests

The detector logic has offline regression tests and does not require live targets to exercise its core classification behavior.

Run:

```bash
python -m unittest discover -s tests -v
```

## License

Licensed under the **Apache License 2.0**. See [LICENSE](LICENSE).

## Author

Emil Veliyev · [@emillvl](https://github.com/emillvl)
