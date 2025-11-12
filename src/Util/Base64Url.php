<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Util;

/**
 * URL-safe Base64 without padding, RFC 4648 §5.
 * - encode(): raw binary -> base64url (no '=')
 * - decode(): base64url -> raw binary (strict; throws on invalid input)
 */
final class Base64Url
{
    public static function encode(string $binary): string
    {
        $b64 = base64_encode($binary);
        return rtrim(strtr($b64, '+/', '-_'), '=');
    }

    public static function decode(string $b64url): string
    {
        if ($b64url !== '' && !preg_match('/^[A-Za-z0-9\-_]+$/', $b64url)) {
            throw new \InvalidArgumentException('Base64Url: invalid characters present.');
        }
        $b64 = strtr($b64url, '-_', '+/');
        $rem = strlen($b64) % 4;
        if ($rem > 0) {
            $b64 .= str_repeat('=', 4 - $rem);
        }
        $out = base64_decode($b64, true);
        if ($out === false) {
            throw new \InvalidArgumentException('Base64Url: invalid base64 encoding.');
        }
        return $out;
    }
}
