<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Http;

use HybridMind\HybridSeal\TokenManager;

/**
 * Double-submit CSRF helper to pair a cookie and a token value.
 *
 * Typical use:
 *   [$cookieName, $cookieHeader, $token] = CsrfCookies::issue($tm, '/checkout', '15m', '.example.com');
 *   // send header: Set-Cookie: $cookieHeader
 *   // also embed $token into a hidden <input> or X-CSRF-Token header for submissions
 */
final class CsrfCookies
{
    /**
     * Issue a CSRF token and a secure Set-Cookie header line containing the same token.
     *
     * @return array{0:string,1:string,2:string} [$cookieName, $setCookieHeader, $token]
     */
    public static function issue(
        TokenManager $manager,
        string $action,
        string|int $ttl = '10m',
        ?string $domain = null,
        string $path = '/',
        bool $secure = true,
        bool $httpOnly = false, // allow JS to read if you send via X-CSRF-Token
        string $sameSite = 'Lax'
    ): array {
        $token = $manager->signCsrf($action, $ttl);
        $cookieName = 'csrf_' . self::slug($action);
        $exp = time() + (is_int($ttl) ? $ttl : self::parseSimpleDuration((string)$ttl));
        $header = Cookie::build($cookieName, $token, $exp, $path, $domain, $secure, $httpOnly, $sameSite);
        return [$cookieName, $header, $token];
    }

    /**
     * Verify the CSRF token using both the cookie value and the submitted value.
     * Throws on failure via TokenManager::verifyCsrf.
     */
    public static function verify(TokenManager $manager, string $action, string $submittedToken): void
    {
        // If you also want to require it equals the cookie value, check equality before verify():
        // hash_equals($submittedToken, $cookieToken)
        $manager->verifyCsrf($action, $submittedToken);
    }

    private static function slug(string $s): string
    {
        $s = strtolower($s);
        $s = preg_replace('/[^a-z0-9]+/', '_', $s) ?? '_';
        return trim($s, '_');
    }

    private static function parseSimpleDuration(string $str): int
    {
        $str = trim($str);
        if ($str === '' || ctype_digit($str)) return (int)$str;
        if (!preg_match('/^(\d+)\s*([smhd])$/i', $str, $m)) return 600;
        $n = (int)$m[1];
        return match (strtolower($m[2])) {
            's' => $n,
            'm' => $n * 60,
            'h' => $n * 3600,
            'd' => $n * 86400,
            default => 600
        };
    }
}
