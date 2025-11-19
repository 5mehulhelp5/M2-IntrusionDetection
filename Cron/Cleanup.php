<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Cron;

use Magento\Framework\App\ResourceConnection;

class Cleanup
{
    public function __construct(private readonly ResourceConnection $rc) {}
    public function execute(): void
    {
        $conn = $this->rc->getConnection();
        // Purge expired blocked IPs
        $conn->delete($this->rc->getTableName('merlin_blocked_ip'), ['expires_at IS NOT NULL','expires_at < UTC_TIMESTAMP()']);
        // Optional: purge events older than 30 days
        $conn->delete($this->rc->getTableName('merlin_intrusion_event'), ["created_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY)"]);
    }
}
