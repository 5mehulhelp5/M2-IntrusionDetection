<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model;

use Magento\Framework\App\ResourceConnection;
use Magento\Framework\DB\Adapter\AdapterInterface;
use Merlin\IntrusionDetection\Api\BlockServiceInterface;

class BlockService implements BlockServiceInterface
{
    private AdapterInterface $conn;
    private string $table;

    public function __construct(private readonly ResourceConnection $resource)
    {
        $this->conn  = $resource->getConnection();
        $this->table = $resource->getTableName('merlin_blocked_ip');
    }

    /**
     * Block an IP. If $minutes <= 0, creates a non-expiring block.
     * Signature must match the interface.
     */
    public function block(string $ip, ?string $reason = null, int $minutes = 60): void
    {
        $ip = trim($ip);
        if ($ip === '') {
            return;
        }

        $expiresExpr = null;
        if ($minutes > 0) {
            $expiresExpr = new \Zend_Db_Expr(
                sprintf('DATE_ADD(UTC_TIMESTAMP(), INTERVAL %d MINUTE)', (int)$minutes)
            );
        }

        $data = [
            'ip'         => $ip,
            'reason'     => (string)($reason ?? ''),
            'created_at' => new \Zend_Db_Expr('UTC_TIMESTAMP()'),
            'expires_at' => $expiresExpr,
        ];

        // Upsert on unique ip
        $this->conn->insertOnDuplicate(
            $this->table,
            $data,
            ['reason', 'created_at', 'expires_at']
        );
    }

    public function unblock(string $ip): void
    {
        $ip = trim($ip);
        if ($ip === '') {
            return;
        }
        $this->conn->delete($this->table, ['ip = ?' => $ip]);
    }

    /**
     * True if IP has a non-expired block.
     * Also purges expired rows opportunistically (UTC-safe).
     */
    public function isBlocked(string $ip): bool
    {
        $ip = trim($ip);
        if ($ip === '') {
            return false;
        }

        // Opportunistic purge
        try {
            $this->conn->delete($this->table, ['expires_at IS NOT NULL', 'expires_at < UTC_TIMESTAMP()']);
        } catch (\Throwable $e) {
            // ignore purge issues
        }

        $select = $this->conn->select()
            ->from($this->table, ['block_id'])
            ->where('ip = ?', $ip)
            ->where('(expires_at IS NULL OR expires_at > UTC_TIMESTAMP())')
            ->limit(1);

        return (bool)$this->conn->fetchOne($select);
    }

    /**
     * List current (non-expired) blocks, newest first.
     * Adjust if your interface defines a different return shape.
     *
     * @return array<int, array<string,mixed>>
     */
    public function listBlocks(): array
    {
        // Purge expired
        try {
            $this->conn->delete($this->table, ['expires_at IS NOT NULL', 'expires_at < UTC_TIMESTAMP()']);
        } catch (\Throwable $e) {}

        $select = $this->conn->select()
            ->from($this->table, ['block_id', 'ip', 'reason', 'created_at', 'expires_at'])
            ->where('(expires_at IS NULL OR expires_at > UTC_TIMESTAMP())')
            ->order('created_at DESC');

        return (array)$this->conn->fetchAll($select);
    }

    /**
     * Optional: extend/refresh expiry in minutes.
     */
    public function extend(string $ip, int $minutes): void
    {
        $ip = trim($ip);
        if ($ip === '' || $minutes <= 0) {
            return;
        }
        $this->conn->update(
            $this->table,
            ['expires_at' => new \Zend_Db_Expr(sprintf('DATE_ADD(UTC_TIMESTAMP(), INTERVAL %d MINUTE)', (int)$minutes))],
            ['ip = ?' => $ip]
        );
    }
}
