<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Http;

final class Cookie
{
    public static function build(
        string $name,
        string $value,
        ?int $expiresAt = null,
        string $path = '/',
        ?string $domain = null,
        bool $secure = true,
        bool $httpOnly = true,
        string $sameSite = 'Lax'
    ): string {
        $nv = rawurlencode($name) . '=' . rawurlencode($value);
        $parts = [$nv];

        if ($expiresAt !== null) {
            $parts[] = 'Expires=' . gmdate('D, d M Y H:i:s T', $expiresAt);
            $parts[] = 'Max-Age=' . max(0, $expiresAt - time());
        }

        $parts[] = 'Path=' . $path;

        if ($domain !== null && $domain !== '') {
            $parts[] = 'Domain=' . $domain;
        }

        if ($secure)   $parts[] = 'Secure';
        if ($httpOnly) $parts[] = 'HttpOnly';

        $ss = ucfirst(strtolower($sameSite));
        if (!in_array($ss, ['Lax', 'Strict', 'None'], true)) {
            $ss = 'Lax';
        }
        $parts[] = 'SameSite=' . $ss;

        return implode('; ', $parts);
    }
}
