<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal;

/**
 * Immutable DTO representing a signed token’s payload.
 */
final class TokenPayload
{
    public readonly int $iat;
    public readonly int $exp;
    public readonly ?int $nbf;
    public readonly string $jti;
    public readonly ?string $aud;
    public readonly ?string $sub;
    /** @var array<string,mixed>|null */
    public readonly ?array $data;

    /**
     * @param array<string,mixed>|null $data
     */
    public function __construct(
        int $iat,
        int $exp,
        ?int $nbf,
        string $jti,
        ?string $aud = null,
        ?string $sub = null,
        ?array $data = null
    ) {
        $this->iat = $iat;
        $this->exp = $exp;
        $this->nbf = $nbf;
        $this->jti = $jti;
        $this->aud = $aud;
        $this->sub = $sub;
        $this->data = $data;
    }

    /** @return array<string,mixed> */
    public function toArray(): array
    {
        $a = [
            'iat' => $this->iat,
            'exp' => $this->exp,
            'jti' => $this->jti,
        ];
        if ($this->nbf !== null) {
            $a['nbf'] = $this->nbf;
        }
        if ($this->aud !== null) {
            $a['aud'] = $this->aud;
        }
        if ($this->sub !== null) {
            $a['sub'] = $this->sub;
        }
        if ($this->data !== null) {
            $a['data'] = $this->data;
        }
        return $a;
    }

    /**
     * @param array<string,mixed> $a
     */
    public static function fromArray(array $a): self
    {
        if (!isset($a['iat'], $a['exp'], $a['jti'])) {
            throw new \InvalidArgumentException('TokenPayload: missing required fields.');
        }

        return new self(
            (int) $a['iat'],
            (int) $a['exp'],
            isset($a['nbf']) ? (int)$a['nbf'] : null,
            (string) $a['jti'],
            $a['aud'] ?? null,
            $a['sub'] ?? null,
            isset($a['data']) && is_array($a['data']) ? $a['data'] : null
        );
    }
}
