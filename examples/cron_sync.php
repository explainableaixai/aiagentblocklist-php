<?php

/**
 * Keep a folder of feed files current. Meant for cron:
 *
 *   15 4 * * * AIAGENTBLOCKLIST_TOKEN=... php /opt/aab/examples/cron_sync.php /var/lib/aab >> /var/log/aab-sync.log 2>&1
 *
 * Only changed files are rewritten (ETag + If-None-Match), so running it
 * every hour costs almost nothing. The exit code is 0 on success, 2 when the
 * subscription has ended, 1 for any other failure.
 */

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use AiAgentBlocklist\Client;
use AiAgentBlocklist\Exception\AccessEndedException;
use AiAgentBlocklist\Exception\AiAgentBlocklistException;

$dir = $argv[1] ?? '/var/lib/aiagentblocklist';
$names = array_slice($argv, 2) ?: ['aab_full.json', 'domains.txt', 'firewall_edl.txt', 'hosts.txt', 'proxy.pac'];

try {
    $client = new Client();
    $changed = $client->sync($dir, $names);
} catch (AccessEndedException $e) {
    fwrite(STDERR, date('c') . " subscription ended or paused; keeping the last good files\n");
    exit(2);
} catch (AiAgentBlocklistException $e) {
    fwrite(STDERR, date('c') . ' sync failed: ' . $e->getMessage() . "\n");
    exit(1);
}

foreach ($changed as $name => $updated) {
    echo date('c'), ' ', str_pad($name, 20), $updated ? ' updated' : ' unchanged', "\n";
}
