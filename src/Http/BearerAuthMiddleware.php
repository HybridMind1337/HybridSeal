<?php
declare(strict_types=1);

namespace HybridMind\HybridSeal\Http;

use HybridMind\HybridSeal\TokenManager;
use HybridMind\HybridSeal\Exceptions\HybridSealException;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class BearerAuthMiddleware implements MiddlewareInterface
{
    private TokenManager $tokens;
    private ResponseFactoryInterface $responseFactory;
    private ?StreamFactoryInterface $streamFactory;

    private ?string $expectedAudience;
    private ?string $expectedSubject;
    private string $realm;
    private bool $allowMissing;

    public function __construct(
        TokenManager $tokens,
        ResponseFactoryInterface $responseFactory,
        ?StreamFactoryInterface $streamFactory = null,
        ?string $expectedAudience = null,
        ?string $expectedSubject = null,
        string $realm = 'HybridSeal',
        bool $allowMissing = false
    ) {
        $this->tokens = $tokens;
        $this->responseFactory = $responseFactory;
        $this->streamFactory = $streamFactory;
        $this->expectedAudience = $expectedAudience;
        $this->expectedSubject = $expectedSubject;
        $this->realm = $realm;
        $this->allowMissing = $allowMissing;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $auth = $request->getHeaderLine('Authorization');

        if ($auth === '') {
            if ($this->allowMissing) {
                return $handler->handle($request);
            }
            return $this->unauthorized('Missing Authorization header');
        }

        if (!preg_match('/^\s*Bearer\s+(\S+)\s*$/i', $auth, $m)) {
            return $this->unauthorized('Invalid Authorization header format');
        }

        $token = $m[1];

        try {
            $payload = $this->tokens->verify($token, $this->expectedAudience, $this->expectedSubject);
        } catch (HybridSealException $e) {
            return $this->unauthorized($e->getMessage());
        } catch (\Throwable $e) {
            return $this->unauthorized('Verification failed');
        }

        $request = $request->withAttribute(AuthAttributes::TOKEN_PAYLOAD, $payload);
        return $handler->handle($request);
    }

    private function unauthorized(string $reason): ResponseInterface
    {
        $resp = $this->responseFactory->createResponse(401)
            ->withHeader('WWW-Authenticate', 'Bearer realm="' . $this->realm . '", error="invalid_token"');

        if ($this->streamFactory) {
            $body = $this->streamFactory->createStream(json_encode([
                'error' => 'unauthorized',
                'error_description' => $reason,
            ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            $resp = $resp
                ->withHeader('Content-Type', 'application/json')
                ->withBody($body);
        }

        return $resp;
    }
}
