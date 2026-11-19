<?php

declare(strict_types=1);

namespace AiAgentBlocklist;

use AiAgentBlocklist\Exception\AccessEndedException;
use AiAgentBlocklist\Exception\AiAgentBlocklistException;
use AiAgentBlocklist\Exception\HttpException;
use AiAgentBlocklist\Exception\NotFoundException;
use AiAgentBlocklist\Exception\TokenException;

/**
 * Feed client for the AI Agent Blocklist (https://www.aiagentblocklist.com).
 *
 * There is no lookup API: the client downloads the feed files behind your
 * private download link, keeps local copies fresh with conditional requests,
 * and parses aab_full.json so every check runs locally.
 */
final class Client
{
    public const VERSION = '1.0.0';
    public const DEFAULT_BASE_URL = 'https://www.aiagentblocklist.com';
    public const TOKEN_ENV = 'AIAGENTBLOCKLIST_TOKEN';
    public const DEFAULT_TIMEOUT = 30;
    public const USER_AGENT = 'aiagentblocklist-php/' . self::VERSION . ' (+https://www.aiagentblocklist.com)';

    /** Every file published behind a download link. */
    public const FILES = [
        'aab_full.csv',
        'aab_full.json',
        'domains.txt',
        'firewall_edl.txt',
        'hosts.txt',
        'proxy.pac',
        'dns_rpz.zone',
        'chrome_extension_blocklist.json',
        'edge_extension_blocklist.json',
        'chrome_edge_extension_blocklist.reg',
        'chrome_edge_extensions.mobileconfig',
        'firefox_extension_ids.txt',
        'macos_bundle_ids.txt',
        'windows_package_ids.txt',
        'process_names.txt',
        'npm_packages.txt',
        'pypi_packages.txt',
        'counts.json',
        'README.txt',
    ];

    private const TOKEN_PATTERN = '/^[A-Za-z0-9]{32}$/D';
    private const FILE_PATTERN = '/^[A-Za-z0-9][A-Za-z0-9_]*\.(csv|json|txt|pac|zone|reg|mobileconfig)$/D';

    /** @var string */
    private $token;
    /** @var string */
    private $baseUrl;
    /** @var int */
    private $timeout;
    /** @var string */
    private $userAgent;
    /** @var callable */
    private $transport;

    /**
     * @param string|null $token   the 32-character token from your download link; null reads AIAGENTBLOCKLIST_TOKEN
     * @param array{base_url?: string, timeout?: int, user_agent?: string, transport?: callable} $options
     *
     * The transport option replaces cURL (tests, other HTTP stacks). It is called as
     * fn(string $method, string $url, array $headers, int $timeout): array{int, array<string,string>, string}
     * and must return [status, lowercase response headers, body].
     *
     * @throws TokenException when the token is missing or malformed (no request is made)
     */
    public function __construct(?string $token = null, array $options = [])
    {
        if ($token === null || trim($token) === '') {
            $env = getenv(self::TOKEN_ENV);
            $token = $env === false ? '' : $env;
        }
        $token = trim($token);
        if ($token === '') {
            throw new TokenException('No token: pass it to the constructor or set ' . self::TOKEN_ENV);
        }
        if (preg_match(self::TOKEN_PATTERN, $token) !== 1) {
            throw new TokenException('The token must be exactly 32 letters and digits, as in your download link');
        }

        $this->token = $token;
        $this->baseUrl = rtrim((string) ($options['base_url'] ?? self::DEFAULT_BASE_URL), '/');
        $this->timeout = max(1, (int) ($options['timeout'] ?? self::DEFAULT_TIMEOUT));
        $this->userAgent = (string) ($options['user_agent'] ?? self::USER_AGENT);
        $this->transport = $options['transport'] ?? [self::class, 'curlTransport'];
    }

    /**
     * URL of the HTML page that lists your files.
     */
    public function fileListUrl(): string
    {
        return $this->baseUrl . '/download/' . $this->token . '/';
    }

    /**
     * Full download URL of one file.
     *
     * @throws AiAgentBlocklistException for a name outside the published naming pattern
     */
    public function fileUrl(string $name): string
    {
        return $this->fileListUrl() . self::checkFileName($name);
    }

    /**
     * Downloads one file and returns its body.
     */
    public function download(string $name): string
    {
        [, , $body] = $this->request('GET', $name, []);

        return $body;
    }

    /**
     * Conditional download into $path.
     *
     * The ETag is kept in "$path.etag" and sent as If-None-Match next time.
     * Returns false when the file was already current (304, or the same ETag
     * after a 200), true when a new version was written. Writes are atomic:
     * a temp file in the same folder is renamed over the target.
     */
    public function downloadTo(string $name, string $path): bool
    {
        self::checkFileName($name);
        $sidecar = $path . '.etag';
        $stored = '';
        if (is_file($path) && is_file($sidecar)) {
            $stored = trim((string) file_get_contents($sidecar));
        }

        $headers = $stored !== '' ? ['If-None-Match: ' . $stored] : [];
        [$status, $responseHeaders, $body] = $this->request('GET', $name, $headers);
        if ($status === 304) {
            return false;
        }

        $etag = isset($responseHeaders['etag']) ? trim($responseHeaders['etag']) : '';
        if ($stored !== '' && $etag !== '' && self::bareEtag($etag) === self::bareEtag($stored)) {
            return false;
        }

        self::writeAtomic($path, $body);
        self::writeAtomic($sidecar, $etag);

        return true;
    }

    /**
     * Keeps a folder in step with the feed.
     *
     * @param string[]|null $names files to fetch; null means every file in FILES
     *
     * @return array<string, bool> file name => whether a new version was written
     */
    public function sync(string $dir, ?array $names = null): array
    {
        $names = $names ?? self::FILES;
        foreach ($names as $name) {
            self::checkFileName((string) $name);
        }
        $dir = rtrim($dir, '/\\');
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new AiAgentBlocklistException("Cannot create folder: $dir");
        }

        $result = [];
        foreach ($names as $name) {
            $result[(string) $name] = $this->downloadTo((string) $name, $dir . DIRECTORY_SEPARATOR . $name);
        }

        return $result;
    }

    /**
     * Downloads aab_full.json and parses it.
     */
    public function loadBlocklist(): Blocklist
    {
        return Blocklist::fromJson($this->download('aab_full.json'));
    }

    /**
     * The comparable core of an ETag: no W/ prefix, no quotes, no -gzip suffix.
     */
    public static function bareEtag(string $etag): string
    {
        $e = trim($etag);
        if (stripos($e, 'W/') === 0) {
            $e = substr($e, 2);
        }
        $e = trim($e, '"');
        if (substr($e, -5) === '-gzip') {
            $e = substr($e, 0, -5);
        }

        return $e;
    }

    /**
     * Validates a feed file name and returns it.
     *
     * @throws AiAgentBlocklistException
     */
    public static function checkFileName(string $name): string
    {
        if (preg_match(self::FILE_PATTERN, $name) !== 1) {
            throw new AiAgentBlocklistException("Invalid file name '$name': expected a name like domains.txt or aab_full.json");
        }

        return $name;
    }

    /**
     * @param string[] $extraHeaders
     *
     * @return array{0: int, 1: array<string, string>, 2: string}
     */
    private function request(string $method, string $name, array $extraHeaders): array
    {
        $url = $this->fileUrl($name);
        $headers = array_merge(['User-Agent: ' . $this->userAgent, 'Accept: */*'], $extraHeaders);

        try {
            $response = ($this->transport)($method, $url, $headers, $this->timeout);
        } catch (AiAgentBlocklistException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new AiAgentBlocklistException('Network error while fetching ' . $name . ': ' . $e->getMessage(), null, $e);
        }

        $status = (int) $response[0];
        $responseHeaders = [];
        foreach ((array) $response[1] as $k => $v) {
            $responseHeaders[strtolower((string) $k)] = (string) $v;
        }
        $body = (string) $response[2];

        if (($status >= 200 && $status < 300) || $status === 304) {
            return [$status, $responseHeaders, $body];
        }
        if ($status === 404) {
            throw new NotFoundException("Not found (404) for $name: the token or the file name is unknown", 404);
        }
        if ($status === 403) {
            throw new AccessEndedException('Access ended (403): the subscription for this token has ended or is paused', 403);
        }

        throw new HttpException("Unexpected HTTP $status while fetching $name", $status);
    }

    /**
     * Default transport using ext-curl. Honours the usual proxy environment variables.
     *
     * @param string[] $headers
     *
     * @return array{0: int, 1: array<string, string>, 2: string}
     */
    public static function curlTransport(string $method, string $url, array $headers, int $timeout): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new AiAgentBlocklistException('Network error: cannot start cURL');
        }
        $responseHeaders = [];
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_NOBODY => $method === 'HEAD',
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => min(15, $timeout),
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_ENCODING => '',
            CURLOPT_HEADERFUNCTION => static function ($handle, string $line) use (&$responseHeaders): int {
                if (stripos($line, 'HTTP/') === 0) {
                    $responseHeaders = [];
                } else {
                    $parts = explode(':', $line, 2);
                    if (count($parts) === 2) {
                        $responseHeaders[strtolower(trim($parts[0]))] = trim($parts[1]);
                    }
                }

                return strlen($line);
            },
        ]);

        $body = curl_exec($ch);
        if ($body === false) {
            $message = curl_error($ch);
            self::closeHandle($ch);
            throw new AiAgentBlocklistException('Network error: ' . $message);
        }
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        self::closeHandle($ch);

        return [$status, $responseHeaders, (string) $body];
    }

    /**
     * curl_close() is a no-op since PHP 8.0 and deprecated in later releases.
     *
     * @param resource|\CurlHandle $ch
     */
    private static function closeHandle($ch): void
    {
        if (PHP_VERSION_ID < 80000) {
            curl_close($ch);
        }
    }

    private static function writeAtomic(string $path, string $data): void
    {
        $dir = dirname($path);
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new AiAgentBlocklistException("Cannot create folder: $dir");
        }
        $tmp = @tempnam($dir, '.aab-');
        if ($tmp === false || @file_put_contents($tmp, $data) === false) {
            throw new AiAgentBlocklistException("Cannot write a temporary file in $dir");
        }
        @chmod($tmp, 0666 & ~umask());
        if (!@rename($tmp, $path)) {
            throw new AiAgentBlocklistException("Cannot move the new version into place: $path");
        }
    }
}
