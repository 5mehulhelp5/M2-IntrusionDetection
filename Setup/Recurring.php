<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Setup;

use Magento\Framework\Setup\InstallSchemaInterface;
use Magento\Framework\Setup\ModuleContextInterface;
use Magento\Framework\Setup\SchemaSetupInterface;

/**
 * Runs on every setup:upgrade.
 * Ensures the legacy MERLIN_BLOCKED_IP_IP index is removed to prevent collisions.
 */
class Recurring implements InstallSchemaInterface
{
    public function install(SchemaSetupInterface $setup, ModuleContextInterface $context)
    {
        $conn  = $setup->getConnection();
        $table = $setup->getTable('merlin_blocked_ip');

        $setup->startSetup();

        try {
            if ($conn->isTableExists($table)) {
                // Reliable across MySQL/MariaDB
                $indexes = $conn->getIndexList($table);
                if (isset($indexes['MERLIN_BLOCKED_IP_IP'])) {
                    $conn->dropIndex($table, 'MERLIN_BLOCKED_IP_IP');
                }
            }
        } catch (\Throwable $e) {
            // Intentionally swallow: never block setup because of this cleanup
        }

        $setup->endSetup();
    }
}
