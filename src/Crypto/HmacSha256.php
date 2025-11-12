<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Crypto;

final class HmacSha256
{
    public static function sign(string $key, string $data): string
    {
        return hash_hmac('sha256', $data, $key, true);
    }

    public static function equals(string $a, string $b): bool
    {
        if (strlen($a) !== strlen($b)) {
            return false;
        }
        return hash_equals($a, $b);
    }
}
