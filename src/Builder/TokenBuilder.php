<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Builder;

use HybridMind\HybridSeal\TokenManager;

final class TokenBuilder
{
    private TokenManager $manager;
    /** @var array<string,mixed>|null */
    private ?array $data = null;
    /** @var array<string,mixed>|null */
    private ?array $header = null;
    private string|int $ttl = '1h';
    private ?string $aud = null;
    private ?string $sub = null;
    private string|int|null $nbf = null;

    public function __construct(TokenManager $manager)
    {
        $this->manager = $manager;
    }

    public function aud(?string $aud): self { $this->aud = $aud; return $this; }
    public function sub(?string $sub): self { $this->sub = $sub; return $this; }
    public function ttl(string|int $ttl): self { $this->ttl = $ttl; return $this; }
    public function notBefore(string|int|null $nbf): self { $this->nbf = $nbf; return $this; }

    /** @param array<string,mixed> $data */
    public function data(array $data): self { $this->data = $data; return $this; }

    /** @param array<string,mixed> $header */
    public function header(array $header): self { $this->header = $header; return $this; }

    public function sign(): string
    {
        return $this->manager->sign(
            data: $this->data,
            expiresIn: $this->ttl,
            aud: $this->aud,
            sub: $this->sub,
            notBefore: $this->nbf,
            headerExtra: $this->header
        );
    }
}
