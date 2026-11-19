<?php

declare(strict_types=1);

namespace AiAgentBlocklist;

use AiAgentBlocklist\Exception\AiAgentBlocklistException;

/**
 * The parsed aab_full.json feed with lookup maps built once at load time.
 *
 * Every check is a hash lookup (domains walk up to one lookup per label),
 * so a Blocklist can sit in a long-running worker and answer many checks.
 *
 * @implements \IteratorAggregate<int, Entry>
 */
final class Blocklist implements \Countable, \IteratorAggregate
{
    public const EXTENSION_KINDS = ['chrome_ext', 'edge_ext', 'firefox_ext', 'vscode_ext', 'openvsx_ext', 'jetbrains_plugin'];
    public const PROCESS_KINDS = ['process_cli', 'process_mac', 'process_win'];

    /** @var string */
    private $product;
    /** @var string */
    private $version;
    /** @var array<string, mixed> */
    private $counts;
    /** @var Entry[] */
    private $entries = [];

    /** @var array<string, Entry> */
    private $byDomain = [];
    /** @var array<string, Entry> */
    private $byExtension = [];
    /** @var array<string, Entry> */
    private $byProcess = [];
    /** @var array<string, Entry> */
    private $byNpm = [];
    /** @var array<string, Entry> */
    private $byPypi = [];
    /** @var array<string, Entry> */
    private $byIdent = [];

    /**
     * @param array<string, mixed> $data the decoded aab_full.json document
     */
    private function __construct(array $data)
    {
        $this->product = isset($data['product']) && is_scalar($data['product']) ? (string) $data['product'] : '';
        $this->version = isset($data['version']) && is_scalar($data['version']) ? (string) $data['version'] : '';
        $this->counts = isset($data['counts']) && is_array($data['counts']) ? $data['counts'] : [];

        foreach ($data['entries'] as $row) {
            if (!is_array($row)) {
                continue;
            }
            $entry = Entry::fromArray($row);
            $this->entries[] = $entry;
            $this->index($entry);
        }
    }

    /**
     * Parses the text of aab_full.json.
     *
     * @throws AiAgentBlocklistException when the text is not a feed document
     */
    public static function fromJson(string $json): self
    {
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new AiAgentBlocklistException('aab_full.json is not valid JSON: ' . json_last_error_msg());
        }

        return self::fromArray($data);
    }

    /**
     * Reads a local copy of aab_full.json, for example one kept fresh by Client::sync().
     *
     * @throws AiAgentBlocklistException when the file cannot be read or parsed
     */
    public static function fromFile(string $path): self
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new AiAgentBlocklistException("Cannot read blocklist file: $path");
        }
        $json = file_get_contents($path);
        if ($json === false) {
            throw new AiAgentBlocklistException("Cannot read blocklist file: $path");
        }

        return self::fromJson($json);
    }

    /**
     * Builds a Blocklist from an already decoded document.
     *
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        if (!isset($data['entries']) || !is_array($data['entries'])) {
            throw new AiAgentBlocklistException('Not an AI Agent Blocklist document: "entries" is missing');
        }

        return new self($data);
    }

    public function product(): string
    {
        return $this->product;
    }

    public function version(): string
    {
        return $this->version;
    }

    /**
     * The "counts" object of the feed, as published.
     *
     * @return array<string, mixed>
     */
    public function counts(): array
    {
        return $this->counts;
    }

    /**
     * @return Entry[]
     */
    public function entries(): array
    {
        return $this->entries;
    }

    public function count(): int
    {
        return count($this->entries);
    }

    /**
     * @return \ArrayIterator<int, Entry>
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->entries);
    }

    /**
     * Matches a host name or URL against the domain entries.
     *
     * The host and every parent domain are tried, so "api.example-agent.ai"
     * matches a listed "example-agent.ai" while "notexample-agent.ai" does not.
     */
    public function checkDomain(string $hostOrUrl): ?Entry
    {
        $host = self::normalizeHost($hostOrUrl);
        while ($host !== '') {
            if (isset($this->byDomain[$host])) {
                return $this->byDomain[$host];
            }
            $dot = strpos($host, '.');
            if ($dot === false) {
                break;
            }
            $host = (string) substr($host, $dot + 1);
        }

        return null;
    }

    /**
     * Exact, case-insensitive match over browser extension and IDE plugin IDs.
     */
    public function checkExtension(string $id): ?Entry
    {
        return $this->byExtension[strtolower(trim($id))] ?? null;
    }

    /**
     * Case-insensitive match over process and command names; "tool.exe" and "tool" match each other.
     */
    public function checkProcess(string $name): ?Entry
    {
        return $this->byProcess[self::processKey($name)] ?? null;
    }

    /**
     * Matches an npm or PyPI package name. PyPI names are compared after PEP 503 normalisation.
     *
     * @throws \InvalidArgumentException for an ecosystem other than npm or pypi
     */
    public function checkPackage(string $ecosystem, string $name): ?Entry
    {
        switch (strtolower(trim($ecosystem))) {
            case 'npm':
                return $this->byNpm[strtolower(trim($name))] ?? null;
            case 'pypi':
                return $this->byPypi[self::normalizePypi($name)] ?? null;
            default:
                throw new \InvalidArgumentException("Unknown package ecosystem '$ecosystem' (use npm or pypi)");
        }
    }

    /**
     * Tries domain matching first, then an exact (case-insensitive) match on any identifier.
     */
    public function check(string $identifier): ?Entry
    {
        $hit = $this->checkDomain($identifier);
        if ($hit !== null) {
            return $hit;
        }

        return $this->byIdent[strtolower(trim($identifier))] ?? null;
    }

    /**
     * Entries matching every criterion given (null means any). Comparison ignores case.
     *
     * @return Entry[]
     */
    public function filter(?string $agentType = null, ?string $kind = null, ?string $riskGrade = null): array
    {
        $out = [];
        foreach ($this->entries as $e) {
            if ($agentType !== null && strcasecmp($e->agentType, $agentType) !== 0) {
                continue;
            }
            if ($kind !== null && strcasecmp($e->kind, $kind) !== 0) {
                continue;
            }
            if ($riskGrade !== null && strcasecmp($e->riskGrade, $riskGrade) !== 0) {
                continue;
            }
            $out[] = $e;
        }

        return $out;
    }

    /**
     * Every listed domain, normalised and sorted.
     *
     * @return string[]
     */
    public function domains(): array
    {
        $list = array_map('strval', array_keys($this->byDomain));
        sort($list);

        return $list;
    }

    /**
     * Distinct agent_type values, sorted.
     *
     * @return string[]
     */
    public function agentTypes(): array
    {
        return $this->distinct(function (Entry $e): string {
            return $e->agentType;
        });
    }

    /**
     * Distinct kind values, sorted.
     *
     * @return string[]
     */
    public function kinds(): array
    {
        return $this->distinct(function (Entry $e): string {
            return $e->kind;
        });
    }

    /**
     * Reduces a URL or host to a bare, lowercase host name.
     *
     * Strips the scheme, user info, port, path, query and fragment, and a trailing dot.
     */
    public static function normalizeHost(string $input): string
    {
        $s = strtolower(trim($input));
        if (preg_match('#^[a-z][a-z0-9+.\-]*://#', $s, $m) === 1) {
            $s = (string) substr($s, strlen($m[0]));
        } elseif (strpos($s, '//') === 0) {
            $s = (string) substr($s, 2);
        }
        $parts = preg_split('#[/?\#\\\\]#', $s, 2);
        $s = $parts === false ? $s : (string) $parts[0];
        $at = strrpos($s, '@');
        if ($at !== false) {
            $s = (string) substr($s, $at + 1);
        }
        if ($s !== '' && $s[0] === '[') {
            $end = strpos($s, ']');
            $s = $end === false ? (string) substr($s, 1) : (string) substr($s, 1, $end - 1);
        } else {
            $colon = strpos($s, ':');
            if ($colon !== false) {
                $s = (string) substr($s, 0, $colon);
            }
        }

        return rtrim($s, '.');
    }

    /**
     * PEP 503 name normalisation: lowercase, and runs of "-", "_" and "." become one "-".
     */
    public static function normalizePypi(string $name): string
    {
        return strtolower((string) preg_replace('/[-_.]+/', '-', trim($name)));
    }

    private static function processKey(string $name): string
    {
        $key = strtolower(trim($name));
        if (strlen($key) > 4 && substr($key, -4) === '.exe') {
            $key = substr($key, 0, -4);
        }

        return $key;
    }

    private function index(Entry $e): void
    {
        $ident = trim($e->ident);
        if ($ident === '') {
            return;
        }
        $lower = strtolower($ident);
        if (!isset($this->byIdent[$lower])) {
            $this->byIdent[$lower] = $e;
        }

        if ($e->kind === 'domain') {
            $host = self::normalizeHost($ident);
            if ($host !== '' && !isset($this->byDomain[$host])) {
                $this->byDomain[$host] = $e;
            }
        } elseif (in_array($e->kind, self::EXTENSION_KINDS, true)) {
            if (!isset($this->byExtension[$lower])) {
                $this->byExtension[$lower] = $e;
            }
        } elseif (in_array($e->kind, self::PROCESS_KINDS, true)) {
            $key = self::processKey($ident);
            if (!isset($this->byProcess[$key])) {
                $this->byProcess[$key] = $e;
            }
        } elseif ($e->kind === 'npm') {
            if (!isset($this->byNpm[$lower])) {
                $this->byNpm[$lower] = $e;
            }
        } elseif ($e->kind === 'pypi') {
            $key = self::normalizePypi($ident);
            if (!isset($this->byPypi[$key])) {
                $this->byPypi[$key] = $e;
            }
        }
    }

    /**
     * @param callable(Entry): string $field
     * @return string[]
     */
    private function distinct(callable $field): array
    {
        $seen = [];
        foreach ($this->entries as $e) {
            $v = $field($e);
            if ($v !== '') {
                $seen[$v] = true;
            }
        }
        $list = array_map('strval', array_keys($seen));
        sort($list);

        return $list;
    }
}
