<?php

/**
 * Read a proxy or web server access log and print every request whose host
 * is on the AI Agent Blocklist. Works offline from a synced aab_full.json.
 *
 *   php examples/check_proxy_log.php /var/lib/aab/aab_full.json /var/log/squid/access.log
 *
 * The script looks for the first URL or host:port in each line, which fits
 * Squid, nginx and most CSV exports. Adjust extractHost() for other formats.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use AiAgentBlocklist\Blocklist;

if ($argc < 3) {
    fwrite(STDERR, "usage: php check_proxy_log.php <aab_full.json> <logfile>\n");
    exit(64);
}

$list = Blocklist::fromFile($argv[1]);
$log = fopen($argv[2], 'rb');
if ($log === false) {
    fwrite(STDERR, "cannot open {$argv[2]}\n");
    exit(66);
}

function extractHost(string $line): ?string
{
    if (preg_match('#\b[a-z][a-z0-9+.\-]*://[^\s"]+#i', $line, $m) === 1) {
        return $m[0];
    }
    if (preg_match('#\b([a-z0-9][a-z0-9.\-]*\.[a-z]{2,}):\d+\b#i', $line, $m) === 1) {
        return $m[1];
    }

    return null;
}

$hits = [];
while (($line = fgets($log)) !== false) {
    $target = extractHost($line);
    if ($target === null) {
        continue;
    }
    $entry = $list->checkDomain($target);
    if ($entry !== null) {
        $key = Blocklist::normalizeHost($target);
        $hits[$key] = $hits[$key] ?? ['count' => 0, 'entry' => $entry];
        $hits[$key]['count']++;
    }
}
fclose($log);

uasort($hits, static function (array $a, array $b): int {
    return $b['count'] <=> $a['count'];
});

printf("%-40s %-24s %-14s %s\n", 'host', 'agent type', 'grade', 'requests');
foreach ($hits as $host => $row) {
    printf("%-40s %-24s %-14s %d\n", $host, $row['entry']->agentType, $row['entry']->riskGrade, $row['count']);
}
