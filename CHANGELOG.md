# Changelog

All notable changes to `alphaquantum/aiagentblocklist` are recorded here. The project follows Semantic Versioning.

## 1.0.0

First release.

- `AiAgentBlocklist\Client`: token from the constructor or `AIAGENTBLOCKLIST_TOKEN`, checked before any request.
- `fileUrl()`, `fileListUrl()`, `download()`, `downloadTo()` (conditional GET with an `.etag` sidecar and atomic writes), `sync()` and `loadBlocklist()`.
- `AiAgentBlocklist\Blocklist` with `fromJson()`, `fromFile()` and `fromArray()`, plus `checkDomain()`, `checkExtension()`, `checkProcess()`, `checkPackage()`, `check()`, `filter()`, `domains()`, `agentTypes()` and `kinds()`. Lookup maps are built once at load time.
- `AiAgentBlocklist\Entry` with the ten feed columns.
- Exceptions: `AiAgentBlocklistException` (base, with `getStatus()`), `NotFoundException` (404), `AccessEndedException` (403), `HttpException` and `TokenException`. Network failures are wrapped in the base class.
- Injectable transport; the PHPUnit suite runs offline.
