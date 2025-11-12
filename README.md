#  HybridSeal

**HybridSeal** is a lightweight, dependency-free PHP library for securely generating and validating **signed, expirable, URL-safe tokens** — perfect for password resets, CSRF protection, API authentication, or any other use where you need short-lived signed data.

It’s designed for **security, simplicity, and performance**, featuring:
- **HMAC-SHA256** signatures with per-audience keys derived via **HKDF**
- **Key rotation** via `KeyStore`
- **Clock skew tolerance** and strict claim validation
- **Replay protection** via pluggable JTI store (Redis or in-memory)
- **CSRF and password reset helpers**
- **Zero external dependencies**
- **CLI tool** (`bin/hybridseal`)
- Optional **PSR-15 middleware** for Bearer authentication
- Full **PHPStan-clean**, **PHPUnit-tested**, and ready for CI

---

## Installation

### Via Composer
```bash
composer require hybridmind/hybridseal
```

---

### Basic Usage
```php
use HybridMind\HybridSeal\KeyStore;
use HybridMind\HybridSeal\TokenManager;

$kid = '2025-11-01';
$secretHex = getenv('HYBRIDSEAL_SECRET_HEX') ?: bin2hex(random_bytes(32));

$keystore = KeyStore::fromHex([$kid => $secretHex], $kid);
$seal = new TokenManager($keystore);

// Sign token valid for 2h
$token = $seal->sign(
    data: ['role' => 'user'],
    expiresIn: '2h',
    aud: 'auth:web',
    sub: 'user_123'
);

// Verify
$payload = $seal->verify($token, expectedAud: 'auth:web');
echo "User: {$payload->sub}, expires at " . date('c', $payload->exp);
```

### CSRF Example
```php
use HybridMind\HybridSeal\Http\CsrfCookies;

[$cookieName, $setCookie, $token] = CsrfCookies::issue($seal, '/checkout', '15m');
header("Set-Cookie: $setCookie");

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    CsrfCookies::verify($seal, '/checkout', $_POST['_token']);
    echo "CSRF token verified";
}
```

### Password Reset Example
```php
$emailHash = hash('sha256', strtolower('user@example.com'));
$resetToken = $seal->signPasswordReset('user_123', $emailHash, '30m');

// In password reset form
$payload = $seal->verifyPasswordReset($resetToken, 'user_123', $emailHash);
```

### CLI Usage
```bash
./bin/hybridseal key:gen --bytes=32
# => 6f0aab8d...

HYBRIDSEAL_SECRET_HEX=6f0aab8d... HYBRIDSEAL_KID=2025-11-01 ./bin/hybridseal sign --ttl=15m --aud=auth:web --sub=user_1
# => eyJhbGciOiJIUzI1NiIsInR5cCI6IkhTRUFM...

HYBRIDSEAL_SECRET_HEX=6f0aab8d... ./bin/hybridseal verify --kid=2025-11-01 --aud=auth:web <token>
```

### KeyStore Rotation
```php
$newKid = '2025-12-01';
$keystore->addKey($newKid, random_bytes(32), makeCurrent: true);
```

### Replay Protection
Use a Redis instance to prevent token replay attacks (based on jti claim):
```php
use HybridMind\HybridSeal\Replay\RedisJtiStore;
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);
$jtiStore = new RedisJtiStore($redis);
$seal = new TokenManager($keystore, clockSkew: 30, jtiStore: $jtiStore);
```
