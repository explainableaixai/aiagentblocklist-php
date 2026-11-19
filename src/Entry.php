<?php

declare(strict_types=1);

namespace AiAgentBlocklist;

/**
 * One row of the AI Agent Blocklist (aab_full.csv / aab_full.json).
 */
final class Entry implements \JsonSerializable
{
    public const FIELDS = [
        'tool_name',
        'tool_domain',
        'category',
        'subcategory',
        'agent_type',
        'kind',
        'ident',
        'name',
        'platform',
        'risk_grade',
    ];

    /** @var string */
    public $toolName;
    /** @var string */
    public $toolDomain;
    /** @var string */
    public $category;
    /** @var string */
    public $subcategory;
    /** @var string */
    public $agentType;
    /** @var string */
    public $kind;
    /** @var string */
    public $ident;
    /** @var string */
    public $name;
    /** @var string */
    public $platform;
    /** @var string */
    public $riskGrade;

    /**
     * @param array<string, mixed> $row a decoded JSON entry or a CSV row keyed by column name
     */
    public static function fromArray(array $row): self
    {
        $e = new self();
        $e->toolName = self::str($row, 'tool_name');
        $e->toolDomain = self::str($row, 'tool_domain');
        $e->category = self::str($row, 'category');
        $e->subcategory = self::str($row, 'subcategory');
        $e->agentType = self::str($row, 'agent_type');
        $e->kind = self::str($row, 'kind');
        $e->ident = self::str($row, 'ident');
        $e->name = self::str($row, 'name');
        $e->platform = self::str($row, 'platform');
        $e->riskGrade = self::str($row, 'risk_grade');

        return $e;
    }

    /**
     * The entry with the original snake_case column names.
     *
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return [
            'tool_name' => $this->toolName,
            'tool_domain' => $this->toolDomain,
            'category' => $this->category,
            'subcategory' => $this->subcategory,
            'agent_type' => $this->agentType,
            'kind' => $this->kind,
            'ident' => $this->ident,
            'name' => $this->name,
            'platform' => $this->platform,
            'risk_grade' => $this->riskGrade,
        ];
    }

    /**
     * @return array<string, string>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }

    /** True when this row is a domain (kind "domain"). */
    public function isDomain(): bool
    {
        return $this->kind === 'domain';
    }

    /**
     * @param array<string, mixed> $row
     */
    private static function str(array $row, string $key): string
    {
        return isset($row[$key]) && is_scalar($row[$key]) ? (string) $row[$key] : '';
    }
}
