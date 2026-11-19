<?php

/**
 * Laravel middleware that refuses outbound links to AI agent domains.
 *
 * Copy to app/Http/Middleware/BlockAiAgentLinks.php, register it as a route
 * middleware, and put it on routes that accept or redirect to user supplied
 * URLs (link shorteners, "open external site" redirects, bookmark forms).
 *
 * The blocklist is read from the folder that cron_sync.php keeps current and
 * cached per worker until the file's modification time changes.
 */

declare(strict_types=1);

namespace App\Http\Middleware;

use AiAgentBlocklist\Blocklist;
use Closure;
use Illuminate\Http\Request;

final class BlockAiAgentLinks
{
    /** @var array{0: int, 1: Blocklist}|null */
    private static $cache;

    /** @var string[] request fields that may carry a URL */
    private $fields = ['url', 'link', 'redirect', 'target'];

    public function handle(Request $request, Closure $next)
    {
        $list = self::blocklist();
        foreach ($this->fields as $field) {
            $value = $request->input($field);
            if (!is_string($value) || $value === '') {
                continue;
            }
            $entry = $list->checkDomain($value);
            if ($entry !== null) {
                abort(403, sprintf('Links to %s (%s) are not allowed here.', $entry->toolName, $entry->agentType));
            }
        }

        return $next($request);
    }

    private static function blocklist(): Blocklist
    {
        $path = config('services.aiagentblocklist.json', storage_path('aab/aab_full.json'));
        clearstatcache(true, $path);
        $mtime = (int) @filemtime($path);
        if (self::$cache === null || self::$cache[0] !== $mtime) {
            self::$cache = [$mtime, Blocklist::fromFile($path)];
        }

        return self::$cache[1];
    }
}
