<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Api;

interface BlockServiceInterface {
    public function block(string $ip, string $reason = null, int $minutes = 60): void;
    public function unblock(string $ip): void;
    public function isBlocked(string $ip): bool;
    /** @return array<array{ip:string, reason:?string, expires_at:?string, created_at:string}> */
    public function listBlocks(): array;
}
