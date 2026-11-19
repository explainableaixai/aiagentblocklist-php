# aiagentblocklist for PHP

PHP runs a large share of the places where people paste links and install things: school portals, intranets, help desks, Laravel back offices and WordPress sites. This package brings the [AI Agent Blocklist](https://www.aiagentblocklist.com/ai-agent-blocklist.php) into those apps. It fetches the feed files from your private download link, keeps local copies current with conditional requests, and answers checks for hosts, URLs, extension IDs, process names and package names straight from memory.

There is no lookup API behind it and no per-request charge. You sync a handful of files once a day (or once an hour, it costs almost nothing), then every check is a PHP array lookup.

```bash
composer require alphaquantum/aiagentblocklist
```

## What the package does

- Downloads any of the 19 published files by name, with your 32-character token.
- Stores each file with an `.etag` sidecar and sends `If-None-Match` on the next run, so unchanged files come back as a short 304.
- Writes new versions atomically (temp file, then rename), which keeps a web server or firewall from ever reading half a file.
- Parses `aab_full.json` into a `Blocklist` object with hash maps built once at load time.
- Matches a host and all of its parent domains on label boundaries, extension IDs exactly, process names with or without `.exe`, and PyPI names after PEP 503 normalisation.
- Throws one exception family with clear subclasses for 404, 403, other HTTP errors and bad tokens.

The feed itself holds 2,600+ AI agent domains and 5,300+ device identifiers. It is rebuilt every day and the file links stay the same, so a cron line written today keeps working.

## Why PHP teams add this list

AI agents and AI browsers do not wait for a person to click. They open pages, fill in forms, read mail and call APIs, and they do it with the signed-in user's cookies, tokens and network position. When nobody approved the agent, nobody checked what it can reach, and the first sign of it is often a strange entry in an access log.

PHP apps are usually the front door for that traffic. A student pastes a link to an agent site into a homework form, a staff member submits a support ticket with an extension ID, or a redirect endpoint gets asked to forward someone to an agent sign-up page. Each of those is a moment where the app can say "this one needs review" before it spreads.

We publish the list so that one decision (which agents are allowed) can be applied in many places at once: the firewall, DNS, browser policy, MDM and your own code. The [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) calls this kind of inventory and control a basic part of governing AI use, and the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) lists excessive agency as a risk of its own.

## Requirements and installation

| Requirement | Version |
|---|---|
| PHP | 7.4 or newer (8.x works) |
| ext-curl | any |
| ext-json | any |
| A subscription | the token from your private download link |

Install with Composer:

```bash
composer require alphaquantum/aiagentblocklist
```

Then put your token where PHP can read it. The constructor takes it as an argument, and when you pass nothing it reads the `AIAGENTBLOCKLIST_TOKEN` environment variable. A token must be exactly 32 letters and digits; anything else throws a `TokenException` before a single request leaves the server.

```bash
# .env, systemd unit, php-fpm pool or crontab
AIAGENTBLOCKLIST_TOKEN=YOUR32CHARACTERTOKENGOESHERE0000
```

Plans and token details are on the [pricing page](https://www.aiagentblocklist.com/pricing.php).

## Quick start in three steps

Sync the files you need, load the JSON once, and ask questions.

```php
<?php
require 'vendor/autoload.php';

use AiAgentBlocklist\Client;
use AiAgentBlocklist\Blocklist;

$client = new Client();                         // reads AIAGENTBLOCKLIST_TOKEN
$client->sync('/var/lib/aab', ['aab_full.json', 'domains.txt']);

$list = Blocklist::fromFile('/var/lib/aab/aab_full.json');

$hit = $list->checkDomain('https://api.example-agent.ai/v1/run');
if ($hit !== null) {
    echo "{$hit->toolName} is listed as {$hit->agentType}\n";
}

var_dump($list->checkExtension('abcdefghijklmnopabcdefghijklmnop') !== null);
var_dump($list->checkProcess('SampleBrowser.exe') !== null);
var_dump($list->checkPackage('pypi', 'Demo_MCP.Server') !== null);
```

All names in these examples are placeholders. The real feed uses the same shape, so the code does not change when you point it at your own copy.

## Worked example 1: a nightly cron sync

Most installs start here. A cron job keeps a folder of files current, and everything else (the firewall, the PAC file on an intranet server, your PHP code) reads from that folder.

```php
<?php
// /opt/aab/sync.php
require '/opt/aab/vendor/autoload.php';

use AiAgentBlocklist\Client;
use AiAgentBlocklist\Exception\AccessEndedException;
use AiAgentBlocklist\Exception\AiAgentBlocklistException;

$files = ['aab_full.json', 'firewall_edl.txt', 'hosts.txt', 'proxy.pac', 'dns_rpz.zone'];

try {
    $changed = (new Client())->sync('/var/www/feeds/aab', $files);
} catch (AccessEndedException $e) {
    error_log('aab: subscription ended or paused, last files stay in place');
    exit(2);
} catch (AiAgentBlocklistException $e) {
    error_log('aab: ' . $e->getMessage());
    exit(1);
}

foreach ($changed as $name => $updated) {
    if ($updated) {
        error_log("aab: new version of $name");
    }
}
```

```cron
# m  h  dom mon dow  command
20   *  *   *   *    AIAGENTBLOCKLIST_TOKEN=... php /opt/aab/sync.php
```

Running it hourly is fine. A file that has not changed costs one small 304 answer and no disk write. When `firewall_edl.txt` does change, the rename is atomic, so a firewall that polls the URL on your intranet web server sees either the old list or the new one.

Our guide to [blocking AI agents at the firewall](https://www.aiagentblocklist.com/network/block-ai-agents-firewall.php) shows where each file goes on the network side. The `proxy.pac` file follows the usual [proxy auto-config](https://en.wikipedia.org/wiki/Proxy_auto-config) format, so browsers that already read a PAC URL can pick it up without extra software.

## Worked example 2: Laravel middleware

Many Laravel apps accept URLs from users: link shorteners, "open external site" redirects, bookmark and resource forms. A route middleware can refuse the ones that point at an AI agent domain.

Bind the blocklist as a singleton first, so each worker parses the JSON once:

```php
// app/Providers/AppServiceProvider.php
use AiAgentBlocklist\Blocklist;

public function register(): void
{
    $this->app->singleton(Blocklist::class, function () {
        return Blocklist::fromFile(storage_path('aab/aab_full.json'));
    });
}
```

Then the middleware itself:

```php
// app/Http/Middleware/BlockAiAgentLinks.php
namespace App\Http\Middleware;

use AiAgentBlocklist\Blocklist;
use Closure;
use Illuminate\Http\Request;

final class BlockAiAgentLinks
{
    public function __construct(private Blocklist $list) {}

    public function handle(Request $request, Closure $next, string ...$fields)
    {
        foreach ($fields ?: ['url'] as $field) {
            $value = $request->input($field);
            if (is_string($value) && ($hit = $this->list->checkDomain($value))) {
                abort(403, "Links to {$hit->toolName} ({$hit->agentType}) need approval.");
            }
        }

        return $next($request);
    }
}
```

```php
// routes/web.php
Route::post('/bookmarks', [BookmarkController::class, 'store'])
    ->middleware(BlockAiAgentLinks::class . ':url,source');
```

Schedule the sync from `app/Console/Kernel.php` (or `routes/console.php` on newer versions) with `$schedule->exec('php /opt/aab/sync.php')->hourly();`. Under Octane or a queue worker the singleton lives for the life of the process, so restart workers after a sync, or use the mtime check in `examples/laravel_middleware.php`, which reloads the file when it changes.

## Worked example 3: a WordPress or school portal check

Schools often run a WordPress site or a small PHP portal where students hand in links and teachers review them. Two things help there: holding submissions that link to agent sites, and giving staff a quick way to look something up.

```php
// wp-content/mu-plugins/aab-link-check.php (shortened; full file in examples/)
use AiAgentBlocklist\Blocklist;

require_once __DIR__ . '/aiagentblocklist/vendor/autoload.php';

function aab_list(): ?Blocklist {
    static $list = null;
    $path = WP_CONTENT_DIR . '/uploads/aab/aab_full.json';
    return $list ??= (is_readable($path) ? Blocklist::fromFile($path) : null);
}

add_filter('pre_comment_approved', function ($approved, array $c) {
    preg_match_all('#https?://[^\s"\'<>]+#i', $c['comment_content'], $m);
    foreach ($m[0] as $url) {
        if (aab_list() && aab_list()->checkDomain($url)) {
            return 0;    // hold for moderation
        }
    }
    return $approved;
}, 20, 2);
```

The full example in `examples/wordpress_school_portal.php` also moves student posts with such links to "pending" and adds an `[aab_check]` shortcode. A teacher pastes a URL, a Chrome extension ID or a process name from a support ticket, and the form answers with the agent type and kind.

The same three functions work in a plain PHP portal without WordPress: load once, call `check()` on whatever the user typed, show the result. Our page on [students and AI agents doing homework](https://www.aiagentblocklist.com/schools/students-ai-agents-homework.php) covers the classroom side of that decision.

## Worked example 4: counting agent traffic in a log

Before blocking anything, many teams first want to know how much agent traffic they have. `examples/check_proxy_log.php` reads a forward proxy or web server log line by line and prints each listed host with its agent type and request count.

```bash
php examples/check_proxy_log.php /var/lib/aab/aab_full.json /var/log/proxy/access.log
```

```text
host                                     agent type               grade          requests
api.example-agent.ai                     Browser agent            High           2
www.sample-browser.app                   AI browser               Elevated       1
```

The output is a good input for an [acceptable use policy for AI agents](https://www.aiagentblocklist.com/guides/ai-agent-acceptable-use-policy.php), because it shows which agent types people already rely on.

## API reference

### `AiAgentBlocklist\Client`

| Method | Returns | What it does |
|---|---|---|
| `__construct(?string $token = null, array $options = [])` | | Token from the argument or `AIAGENTBLOCKLIST_TOKEN`. Options: `base_url`, `timeout` (seconds, default 30), `user_agent`, `transport`. |
| `fileListUrl()` | `string` | URL of the HTML page that lists your files. |
| `fileUrl(string $name)` | `string` | Full URL of one file; rejects names outside the published pattern. |
| `download(string $name)` | `string` | The body of one file. |
| `downloadTo(string $name, string $path)` | `bool` | Conditional GET with an `.etag` sidecar; `true` when a new version was written. |
| `sync(string $dir, ?array $names = null)` | `array<string,bool>` | `downloadTo()` for each name (all 19 files by default). |
| `loadBlocklist()` | `Blocklist` | Downloads and parses `aab_full.json`. |
| `Client::bareEtag(string $etag)` | `string` | ETag without `W/`, quotes or a `-gzip` suffix. |
| `Client::FILES` | `string[]` | Every published file name. |

### `AiAgentBlocklist\Blocklist`

| Method | Returns | What it does |
|---|---|---|
| `Blocklist::fromFile(string $path)` | `Blocklist` | Reads a local `aab_full.json`. |
| `Blocklist::fromJson(string $json)` | `Blocklist` | Parses JSON text. |
| `Blocklist::fromArray(array $data)` | `Blocklist` | Uses an already decoded document. |
| `version()`, `product()`, `counts()` | `string`, `string`, `array` | Feed metadata as published. |
| `entries()` | `Entry[]` | Every row; the object is also `Countable` and iterable. |
| `checkDomain(string $hostOrUrl)` | `?Entry` | Host or any parent domain, kind `domain` only. |
| `checkExtension(string $id)` | `?Entry` | Browser extension and IDE plugin IDs, case-insensitive. |
| `checkProcess(string $name)` | `?Entry` | Process and command names; `tool.exe` equals `tool`. |
| `checkPackage(string $ecosystem, string $name)` | `?Entry` | `npm` (lowercase, exact) or `pypi` (PEP 503). |
| `check(string $identifier)` | `?Entry` | Domain match first, then any exact identifier. |
| `filter(?string $agentType, ?string $kind, ?string $riskGrade)` | `Entry[]` | Rows that match every given value. |
| `domains()`, `agentTypes()`, `kinds()` | `string[]` | Sorted distinct values. |

`Entry` has ten public properties that mirror the CSV columns: `toolName`, `toolDomain`, `category`, `subcategory`, `agentType`, `kind`, `ident`, `name`, `platform` and `riskGrade`. It implements `JsonSerializable` and `toArray()` gives back the original snake_case keys.

## How matching works

Domain checks accept almost anything a user or a log can hand you. The input is lowercased, the scheme, user info, port, path, query and fragment are removed, and a trailing dot is dropped. Then the host is tried, followed by each parent domain in turn.

| Input | Host that is checked | Listed `example-agent.ai` matches? |
|---|---|---|
| `https://API.Example-Agent.ai/v1?x=1` | `api.example-agent.ai` | yes, through the parent |
| `user:pw@example-agent.ai:8443` | `example-agent.ai` | yes |
| `example-agent.ai.` | `example-agent.ai` | yes |
| `notexample-agent.ai` | `notexample-agent.ai` | no, different label |
| `example-agent.ai.other.test` | `example-agent.ai.other.test` | no |

Extension IDs, bundle IDs and package IDs are compared exactly, ignoring case. Process names drop a trailing `.exe` on both sides, so a Windows name and a bare command name meet in the middle. PyPI names follow [PEP 503](https://peps.python.org/pep-0503/): `Demo_MCP.Server` and `demo-mcp-server` are the same package.

## Errors and status codes

Everything the package throws extends `AiAgentBlocklistException`, which has `getStatus()`. It returns the HTTP status for server answers and `null` for local problems.

| Exception | When | Status |
|---|---|---|
| `TokenException` | token missing or not 32 letters and digits | `null` |
| `NotFoundException` | unknown token, or a file name that does not exist | 404 |
| `AccessEndedException` | subscription ended or paused | 403 |
| `HttpException` | any other non-2xx answer | the status |
| `AiAgentBlocklistException` | invalid file name, network failure, unreadable JSON | `null` |

```php
try {
    $client->sync($dir);
} catch (AccessEndedException $e) {
    notify_admin('AI Agent Blocklist access has ended; renew to keep updates.');
} catch (NotFoundException $e) {
    notify_admin('Check the token in AIAGENTBLOCKLIST_TOKEN.');
} catch (AiAgentBlocklistException $e) {
    error_log('aab sync failed, will retry next run: ' . $e->getMessage());
}
```

A failed sync never touches the files already on disk. Messages never include the token, so they are safe to send to a log service.

## Files behind your link

The feed has nineteen files, and a typical PHP site touches only a few of them. Here they are grouped by who reads them:

- **Your PHP code.** `aab_full.json` is what `Blocklist::fromFile()` parses. `counts.json` holds totals per kind, agent type and grade, which makes a tidy widget on an admin page.
- **Systems that fetch from your web server.** Put `proxy.pac` where staff browsers expect their PAC URL, and `firewall_edl.txt` where the firewall polls for its external list. Both change in place with each sync.
- **Your database.** Load `aab_full.csv` into a MySQL or PostgreSQL table with `LOAD DATA` or `COPY` when reports need SQL joins against your own user or device records.
- **Machines without a central filter.** Copy `hosts.txt` to lab computers, give `dns_rpz.zone` to the school resolver, and use `domains.txt` anywhere a tool wants one bare name per line.
- **Browser administrators.** The Chrome and Edge policy files carry extension IDs in the format each browser's install blocklist policy expects.

`README.txt` explains every file in plain text, including the ones not listed here. The browser policy files pair well with our page on [blocking AI browser extensions](https://www.aiagentblocklist.com/extensions/block-ai-browser-extensions.php), and the [AI browser blocking guide](https://www.aiagentblocklist.com/ai-browsers/block-ai-browsers.php) shows which identifiers MDM and endpoint tools use for AI browsers installed as full apps.

Laravel, WordPress and the browsers named in this README belong to their makers. Product names are trademarks of their respective owners.

## Running it in production

- **Memory.** A parsed feed is a few megabytes. Under PHP-FPM, load it once per request only where you need it; under Octane, Swoole or RoadRunner, keep it in a singleton.
- **OPcache.** The JSON is data, not code, so OPcache does not hold it. If you want zero parse cost per request, cache `Blocklist::fromFile()` in APCu keyed by the file's `filemtime()`.
- **Permissions.** New files are written with your umask, then renamed. Give the cron user write access to the folder and the web server read access.
- **Shared hosting.** If you cannot run cron, call `sync()` from a scheduled task in your control panel. The conditional request keeps it cheap.
- **Proxies.** The default transport uses cURL, which honours `HTTPS_PROXY`. For anything unusual, pass your own `transport` callable.
- **Timeouts.** The default is 30 seconds per request. The full JSON is the largest file; raise `timeout` on slow links.

## Testing your own code

The constructor accepts a `transport` callable, so your tests never need the network:

```php
$client = new Client(str_repeat('a', 32), [
    'transport' => fn ($method, $url, $headers, $timeout) => [200, ['etag' => '"t1"'], $fixtureJson],
]);
```

For code that only checks, skip the client and build the list from a small fixture with `Blocklist::fromJson()`. This package's own PHPUnit suite does exactly that: `composer install && composer test` runs it offline.

## FAQ

### Does every check call your server?

No. The package downloads files and parses them locally. After a sync, `checkDomain()` and friends run in your PHP process with no network access at all.

### How often should cron run the sync?

Once a day is enough to stay current, since the feed is rebuilt every day. Hourly runs are fine too; unchanged files answer with 304 and nothing is rewritten.

### Will it work on PHP 8.3?

Yes. The code is written for PHP 7.4 and uses nothing that later 8.x releases removed. It has no dependencies beyond ext-curl and ext-json.

### What happens to my files when the subscription ends?

The server answers 403, `sync()` throws `AccessEndedException`, and the files from the last good run stay where they are. Your app keeps working with that copy until you renew or remove it.

### Why does a subdomain match a listed domain?

Agents often use many hosts under one name: `api.`, `app.`, `cdn.` and so on. Matching on label boundaries catches all of them while leaving look-alike names such as `notexample-agent.ai` alone.

### Can I allow one agent and block the rest?

Yes. Filter it out in your own code before you act on a hit, or build your own lists with `filter()`. The feed is the same for everyone; the policy is yours.

### Where do I report a missing agent or a wrong entry?

Write to us through the [contact page](https://www.aiagentblocklist.com/contact.php) or at info@alpha-quantum.com. Include the domain or identifier and what you saw.

## Links

- Product: [AI Agent Blocklist](https://www.aiagentblocklist.com/ai-agent-blocklist.php)
- Source: [github.com/explainableaixai/aiagentblocklist-php](https://github.com/explainableaixai/aiagentblocklist-php)
- Package: [packagist.org/packages/alphaquantum/aiagentblocklist](https://packagist.org/packages/alphaquantum/aiagentblocklist)
- Background reading: [CISA on artificial intelligence](https://www.cisa.gov/ai)
- Support: info@alpha-quantum.com

## License

The code is MIT licensed; the terms are in [LICENSE](LICENSE). Copyright (c) 2026 Alpha Quantum.

## Related

If you also need a wider list of AI tools, see the [AI tools blocklist](https://www.aitoolsblocklist.com). For mobile apps on managed devices there is an [app blocklist for MDM](https://www.appblocklist.com). For general website categories, try the [web filtering database](https://www.webfilteringdatabase.com).
