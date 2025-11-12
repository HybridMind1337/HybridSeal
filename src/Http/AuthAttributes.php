<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Http;

/**
 * Common request attribute names used by the BearerAuthMiddleware.
 */
final class AuthAttributes
{
    /**
     * PSR-7 attribute key under which TokenPayload is attached to the request.
     */
    public const TOKEN_PAYLOAD = 'hybridseal.token_payload';
}
