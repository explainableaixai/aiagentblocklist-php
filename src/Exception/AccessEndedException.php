<?php

declare(strict_types=1);

namespace AiAgentBlocklist\Exception;

/**
 * HTTP 403: the subscription behind the token has ended or is paused.
 */
class AccessEndedException extends AiAgentBlocklistException
{
}
