<?php

declare(strict_types=1);

namespace AiAgentBlocklist\Exception;

/**
 * The token is missing or is not 32 letters and digits. Thrown before any request.
 */
class TokenException extends AiAgentBlocklistException
{
}
