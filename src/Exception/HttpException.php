<?php

declare(strict_types=1);

namespace AiAgentBlocklist\Exception;

/**
 * Any other non-2xx answer (for example 500 or 503).
 */
class HttpException extends AiAgentBlocklistException
{
}
