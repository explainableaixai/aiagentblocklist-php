<?php

declare(strict_types=1);

namespace AiAgentBlocklist\Tests;

use AiAgentBlocklist\Blocklist;
use AiAgentBlocklist\Client;
use AiAgentBlocklist\Entry;
use AiAgentBlocklist\Exception\AccessEndedException;
use AiAgentBlocklist\Exception\AiAgentBlocklistException;
use AiAgentBlocklist\Exception\HttpException;
use AiAgentBlocklist\Exception\NotFoundException;
use AiAgentBlocklist\Exception\TokenException;
use PHPUnit\Framework\TestCase;

/**
 * Offline tests: a fake transport answers every request, and the feed is a
 * fixture with made-up entries.
 */
final class ClientTest extends TestCase
{
    private const TOKEN = 'abcdEFGH1234abcdEFGH1234abcdEFGH';

    /** @var string */
    private static $fixture;

    public static function setUpBeforeClass(): void
    {
        self::$fixture = (string) file_get_contents(__DIR__ . '/fixtures/aab_full.json');
    }

    private function blocklist(): Blocklist
    {
        return Blocklist::fromJson(self::$fixture);
    }

    private function tempDir(): string
    {
        $dir = sys_get_temp_dir() . '/aab-php-test-' . bin2hex(random_bytes(6));
        mkdir($dir, 0775, true);

        return $dir;
    }

    /**
     * @param callable $handler fn(string $method, string $url, array $headers): array
     */
    private function client(callable $handler): Client
    {
        return new Client(self::TOKEN, [
            'transport' => static function (string $method, string $url, array $headers, int $timeout) use ($handler): array {
                return $handler($method, $url, $headers);
            },
        ]);
    }

    // Token and file names

    public function testTokenFromEnvironment(): void
    {
        putenv(Client::TOKEN_ENV . '=' . self::TOKEN);
        try {
            $client = new Client(null, ['transport' => static function (): array {
                return [200, [], ''];
            }]);
            $this->assertSame(
                'https://www.aiagentblocklist.com/download/' . self::TOKEN . '/domains.txt',
                $client->fileUrl('domains.txt')
            );
        } finally {
            putenv(Client::TOKEN_ENV);
        }
    }

    /**
     * @dataProvider badTokens
     */
    public function testBadTokenIsRejectedBeforeAnyRequest(string $token): void
    {
        putenv(Client::TOKEN_ENV);
        $called = false;
        try {
            new Client($token, ['transport' => static function () use (&$called): array {
                $called = true;

                return [200, [], ''];
            }]);
            $this->fail('expected TokenException');
        } catch (TokenException $e) {
            $this->assertInstanceOf(AiAgentBlocklistException::class, $e);
            $this->assertNull($e->getStatus());
        }
        $this->assertFalse($called);
    }

    /**
     * @return array<string, array{string}>
     */
    public function badTokens(): array
    {
        return [
            'empty' => [''],
            'short' => ['abc123'],
            'symbols' => ['abcdEFGH1234abcdEFGH1234abcdEF-!'],
            'too long' => [self::TOKEN . 'x'],
            'newline' => [self::TOKEN . "\nX"],
        ];
    }

    public function testFileUrlAndListUrl(): void
    {
        $client = new Client(self::TOKEN, ['base_url' => 'http://127.0.0.1:8080/']);
        $this->assertSame('http://127.0.0.1:8080/download/' . self::TOKEN . '/', $client->fileListUrl());
        $this->assertSame('http://127.0.0.1:8080/download/' . self::TOKEN . '/proxy.pac', $client->fileUrl('proxy.pac'));
        $this->assertSame('README.txt', Client::checkFileName('README.txt'));
    }

    /**
     * @dataProvider badFileNames
     */
    public function testBadFileNamesAreRejected(string $name): void
    {
        $client = $this->client(function (): array {
            $this->fail('no request expected');
        });
        $this->expectException(AiAgentBlocklistException::class);
        $client->download($name);
    }

    /**
     * @return array<string, array{string}>
     */
    public function badFileNames(): array
    {
        return [
            'traversal' => ['../etc/passwd'],
            'slash' => ['sub/domains.txt'],
            'leading underscore' => ['_domains.txt'],
            'dash' => ['my-file.txt'],
            'unknown extension' => ['domains.exe'],
            'no extension' => ['domains'],
            'query' => ['domains.txt?x=1'],
            'trailing newline' => ["domains.txt\n"],
        ];
    }

    // HTTP behaviour

    public function testDownloadSendsUserAgent(): void
    {
        $seen = [];
        $client = $this->client(static function (string $method, string $url, array $headers) use (&$seen): array {
            $seen = [$method, $url, $headers];

            return [200, ['ETag' => '"v1"'], "example-agent.ai\n"];
        });

        $this->assertSame("example-agent.ai\n", $client->download('domains.txt'));
        $this->assertSame('GET', $seen[0]);
        $this->assertStringEndsWith('/download/' . self::TOKEN . '/domains.txt', $seen[1]);
        $this->assertContains('User-Agent: aiagentblocklist-php/1.0.0 (+https://www.aiagentblocklist.com)', $seen[2]);
    }

    public function testStatusCodesMapToExceptions(): void
    {
        $cases = [404 => NotFoundException::class, 403 => AccessEndedException::class, 500 => HttpException::class, 429 => HttpException::class];
        foreach ($cases as $status => $class) {
            $client = $this->client(static function () use ($status): array {
                return [$status, [], 'nope'];
            });
            try {
                $client->download('hosts.txt');
                $this->fail("no exception for $status");
            } catch (AiAgentBlocklistException $e) {
                $this->assertInstanceOf($class, $e);
                $this->assertSame($status, $e->getStatus());
                $this->assertStringNotContainsString(self::TOKEN, $e->getMessage());
            }
        }
    }

    public function testNetworkErrorsAreWrapped(): void
    {
        $client = $this->client(static function (): array {
            throw new \RuntimeException('connection refused');
        });
        try {
            $client->download('counts.json');
            $this->fail('expected exception');
        } catch (AiAgentBlocklistException $e) {
            $this->assertNull($e->getStatus());
            $this->assertStringContainsString('connection refused', $e->getMessage());
            $this->assertInstanceOf(\RuntimeException::class, $e->getPrevious());
        }
    }

    // Conditional downloads

    public function testDownloadToWritesFileAndSidecarThenUses304(): void
    {
        $dir = $this->tempDir();
        $path = $dir . '/domains.txt';
        $requests = [];
        $client = $this->client(static function (string $method, string $url, array $headers) use (&$requests): array {
            $requests[] = $headers;
            foreach ($headers as $h) {
                if ($h === 'If-None-Match: "abc123"') {
                    return [304, [], ''];
                }
            }

            return [200, ['etag' => '"abc123"'], "example-agent.ai\n"];
        });

        $this->assertTrue($client->downloadTo('domains.txt', $path));
        $this->assertSame("example-agent.ai\n", file_get_contents($path));
        $this->assertSame('"abc123"', file_get_contents($path . '.etag'));
        $this->assertNotContains('If-None-Match: "abc123"', $requests[0]);

        $this->assertFalse($client->downloadTo('domains.txt', $path));
        $this->assertContains('If-None-Match: "abc123"', $requests[1]);
        $this->assertSame("example-agent.ai\n", file_get_contents($path));
        $this->assertSame([], glob($dir . '/.aab-*'));
    }

    public function testWeakGzipEtagCountsAsUnchanged(): void
    {
        $dir = $this->tempDir();
        $path = $dir . '/hosts.txt';
        file_put_contents($path, "0.0.0.0 example-agent.ai\n");
        file_put_contents($path . '.etag', '"5f2-63a"');
        $client = $this->client(static function (): array {
            return [200, ['etag' => 'W/"5f2-63a-gzip"'], "changed body\n"];
        });

        $this->assertFalse($client->downloadTo('hosts.txt', $path));
        $this->assertSame("0.0.0.0 example-agent.ai\n", file_get_contents($path));
    }

    public function testNewEtagReplacesFile(): void
    {
        $dir = $this->tempDir();
        $path = $dir . '/hosts.txt';
        file_put_contents($path, "old\n");
        file_put_contents($path . '.etag', '"v1"');
        $client = $this->client(static function (): array {
            return [200, ['ETag' => '"v2"'], "new\n"];
        });

        $this->assertTrue($client->downloadTo('hosts.txt', $path));
        $this->assertSame("new\n", file_get_contents($path));
        $this->assertSame('"v2"', file_get_contents($path . '.etag'));
    }

    public function testSidecarIsIgnoredWhenFileIsMissing(): void
    {
        $dir = $this->tempDir();
        $path = $dir . '/proxy.pac';
        file_put_contents($path . '.etag', '"stale"');
        $sent = null;
        $client = $this->client(static function (string $m, string $u, array $headers) use (&$sent): array {
            $sent = $headers;

            return [200, ['etag' => '"stale"'], 'function FindProxyForURL(url, host) { return "DIRECT"; }'];
        });

        $this->assertTrue($client->downloadTo('proxy.pac', $path));
        $this->assertNotContains('If-None-Match: "stale"', (array) $sent);
        $this->assertFileExists($path);
    }

    public function testBareEtag(): void
    {
        $this->assertSame('abc', Client::bareEtag('W/"abc-gzip"'));
        $this->assertSame('abc', Client::bareEtag('"abc"'));
        $this->assertSame('abc', Client::bareEtag(' abc '));
    }

    public function testSyncReturnsUpdatedMap(): void
    {
        $dir = $this->tempDir() . '/feed';
        $client = $this->client(static function (string $method, string $url, array $headers): array {
            if (in_array('If-None-Match: "same"', $headers, true)) {
                return [304, [], ''];
            }

            return [200, ['etag' => '"same"'], basename($url) . "\n"];
        });

        $first = $client->sync($dir, ['domains.txt', 'aab_full.json']);
        $this->assertSame(['domains.txt' => true, 'aab_full.json' => true], $first);
        $this->assertSame("aab_full.json\n", file_get_contents($dir . '/aab_full.json'));

        $second = $client->sync($dir, ['domains.txt', 'aab_full.json']);
        $this->assertSame(['domains.txt' => false, 'aab_full.json' => false], $second);
        $this->assertCount(19, Client::FILES);
    }

    public function testSyncValidatesNamesBeforeDownloading(): void
    {
        $client = $this->client(function (): array {
            $this->fail('no request expected');
        });
        $this->expectException(AiAgentBlocklistException::class);
        $client->sync($this->tempDir(), ['domains.txt', '../x.txt']);
    }

    public function testLoadBlocklist(): void
    {
        $client = $this->client(static function (string $m, string $url): array {
            return [200, [], self::$fixture];
        });
        $list = $client->loadBlocklist();
        $this->assertSame('fixture-1', $list->version());
        $this->assertCount(12, $list);
    }

    // Blocklist

    public function testFromFileAndMetadata(): void
    {
        $list = Blocklist::fromFile(__DIR__ . '/fixtures/aab_full.json');
        $this->assertSame('AI Agent Blocklist', $list->product());
        $this->assertSame('fixture-1', $list->version());
        $this->assertSame(12, $list->counts()['total']);
        $this->assertContainsOnlyInstancesOf(Entry::class, $list->entries());
        $this->assertSame('example-agent.ai', $list->entries()[0]->toArray()['ident']);
    }

    public function testInvalidDocumentsAreRejected(): void
    {
        $this->expectException(AiAgentBlocklistException::class);
        Blocklist::fromJson('{"product": "x"}');
    }

    public function testDomainSuffixMatching(): void
    {
        $list = $this->blocklist();
        $this->assertSame('Example Agent', $list->checkDomain('example-agent.ai')->toolName);
        $this->assertSame('Example Agent', $list->checkDomain('api.example-agent.ai')->toolName);
        $this->assertSame('Example Agent', $list->checkDomain('a.b.c.example-agent.ai')->toolName);
        $this->assertNull($list->checkDomain('notexample-agent.ai'));
        $this->assertNull($list->checkDomain('example-agent.ai.evil.test'));
        $this->assertNull($list->checkDomain('ai'));
        $this->assertNull($list->checkDomain(''));
    }

    /**
     * @dataProvider urls
     */
    public function testUrlNormalisation(string $input, string $host): void
    {
        $this->assertSame($host, Blocklist::normalizeHost($input));
        $this->assertNotNull($this->blocklist()->checkDomain($input), $input);
    }

    /**
     * @return array<int, array{string, string}>
     */
    public function urls(): array
    {
        return [
            ['https://API.Example-Agent.ai/v1/run?x=1#top', 'api.example-agent.ai'],
            ['http://user:secret@sample-browser.app:8443/path', 'sample-browser.app'],
            ['sample-browser.app.', 'sample-browser.app'],
            ['  Demo-MCP-Server.dev:443  ', 'demo-mcp-server.dev'],
            ['//cdn.example-agent.ai/x.js', 'cdn.example-agent.ai'],
            ['wss://live.sample-browser.app/socket', 'live.sample-browser.app'],
        ];
    }

    public function testOnlyDomainKindCountsForDomains(): void
    {
        $list = $this->blocklist();
        $this->assertNull($list->checkDomain('com.example.agentbrowser'));
        $this->assertSame(['demo-mcp-server.dev', 'example-agent.ai', 'sample-browser.app'], $list->domains());
    }

    public function testExtensionMatchIsExactAndCaseInsensitive(): void
    {
        $list = $this->blocklist();
        $this->assertSame('chrome_ext', $list->checkExtension('ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP')->kind);
        $this->assertSame('firefox_ext', $list->checkExtension('agent-helper@example.org')->kind);
        $this->assertSame('vscode_ext', $list->checkExtension('examplecorp.example-coder')->kind);
        $this->assertNull($list->checkExtension('abcdefghijklmnopabcdefghijklmno'));
        $this->assertNull($list->checkExtension('example-agent.ai'));
    }

    public function testProcessMatchingWithExe(): void
    {
        $list = $this->blocklist();
        $this->assertSame('process_win', $list->checkProcess('samplebrowser')->kind);
        $this->assertSame('process_win', $list->checkProcess('SAMPLEBROWSER.EXE')->kind);
        $this->assertSame('process_cli', $list->checkProcess('example-coder.exe')->kind);
        $this->assertSame('process_mac', $list->checkProcess('sample browser helper')->kind);
        $this->assertNull($list->checkProcess('example'));
    }

    public function testPackages(): void
    {
        $list = $this->blocklist();
        $this->assertSame('npm', $list->checkPackage('npm', 'Demo-MCP-Server')->kind);
        $this->assertNull($list->checkPackage('npm', 'demo_mcp_server'));
        $this->assertSame('pypi', $list->checkPackage('pypi', 'demo-mcp-server')->kind);
        $this->assertSame('pypi', $list->checkPackage('PyPI', 'DEMO__mcp..server')->kind);
        $this->assertSame('demo-mcp-server', Blocklist::normalizePypi('Demo_MCP.Server'));
        $this->expectException(\InvalidArgumentException::class);
        $list->checkPackage('cargo', 'demo');
    }

    public function testCheckTriesDomainThenIdent(): void
    {
        $list = $this->blocklist();
        $this->assertSame('domain', $list->check('https://www.sample-browser.app/download')->kind);
        $this->assertSame('mac_bundle_id', $list->check('COM.EXAMPLE.AGENTBROWSER')->kind);
        $this->assertSame('firefox_ext', $list->check('agent-helper@example.org')->kind);
        $this->assertSame('process_win', $list->check('SampleBrowser.exe')->kind);
        $this->assertNull($list->check('nothing-here.example'));
    }

    public function testFilterAndFacets(): void
    {
        $list = $this->blocklist();
        $this->assertCount(4, $list->filter('AI browser'));
        $this->assertCount(1, $list->filter('ai browser', 'domain'));
        $this->assertCount(3, $list->filter(null, null, 'High'));
        $this->assertCount(2, $list->filter('Coding agent', null, 'Not graded'));
        $this->assertCount(0, $list->filter('Voice agent'));
        $this->assertSame(['AI browser', 'Browser agent', 'Coding agent', 'MCP server'], $list->agentTypes());
        $this->assertContains('jetbrains_plugin', Blocklist::EXTENSION_KINDS);
        $this->assertSame(
            ['chrome_ext', 'domain', 'firefox_ext', 'mac_bundle_id', 'npm', 'process_cli', 'process_mac', 'process_win', 'pypi', 'vscode_ext'],
            $list->kinds()
        );
    }

    public function testEntryJson(): void
    {
        $entry = $this->blocklist()->checkDomain('example-agent.ai');
        $round = json_decode((string) json_encode($entry), true);
        $this->assertSame(Entry::FIELDS, array_keys($round));
        $this->assertSame('Browser agent', $round['agent_type']);
    }
}
