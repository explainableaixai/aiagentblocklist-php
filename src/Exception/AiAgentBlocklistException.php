<?php

declare(strict_types=1);

namespace AiAgentBlocklist\Exception;

/**
 * Base class for every error this package throws.
 *
 * getStatus() returns the HTTP status for answers from the server and null
 * for local problems (bad token, bad file name, network failure, bad JSON).
 */
class AiAgentBlocklistException extends \RuntimeException
{
    /** @var int|null */
    private $status;

    public function __construct(string $message, ?int $status = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, $status ?? 0, $previous);
        $this->status = $status;
    }

    public function getStatus(): ?int
    {
        return $this->status;
    }
}
