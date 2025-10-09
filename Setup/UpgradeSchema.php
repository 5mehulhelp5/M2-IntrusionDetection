<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Setup;

use Magento\Framework\DB\Adapter\AdapterInterface;
use Magento\Framework\DB\Ddl\Table;
use Magento\Framework\Setup\UpgradeSchemaInterface;
use Magento\Framework\Setup\ModuleContextInterface;
use Magento\Framework\Setup\SchemaSetupInterface;

class UpgradeSchema implements UpgradeSchemaInterface
{
    public function upgrade(SchemaSetupInterface $setup, ModuleContextInterface $context)
    {
        $conn = $setup->getConnection();
        $setup->startSetup();

        $eventTable = $setup->getTable('merlin_intrusion_event');
        $blockTable = $setup->getTable('merlin_blocked_ip');

        // 1) Ensure tables exist (create if missing)
        if (!$conn->isTableExists($eventTable)) {
            $table = $conn->newTable($eventTable)
                ->setComment('Intrusion Events')
                ->addColumn('event_id', Table::TYPE_INTEGER, null, ['identity' => true, 'unsigned' => true, 'nullable' => false, 'primary' => true], 'ID')
                ->addColumn('created_at', Table::TYPE_TIMESTAMP, null, ['nullable' => false, 'default' => Table::TIMESTAMP_INIT], 'Created At (UTC)')
                ->addColumn('ip', Table::TYPE_TEXT, 45, ['nullable' => false], 'Client IP')
                ->addColumn('path', Table::TYPE_TEXT, 1024, ['nullable' => false], 'Request Path')
                ->addColumn('user_agent', Table::TYPE_TEXT, 512, ['nullable' => true], 'User Agent')
                ->addColumn('detector', Table::TYPE_TEXT, 128, ['nullable' => false], 'Detector Name')
                ->addColumn('severity', Table::TYPE_TEXT, 32, ['nullable' => false, 'default' => 'low'], 'Severity')
                ->addColumn('details', Table::TYPE_TEXT, null, ['nullable' => true], 'Details')
                ->addIndex($setup->getIdxName($eventTable, ['ip'], AdapterInterface::INDEX_TYPE_INDEX), ['ip'], ['type' => AdapterInterface::INDEX_TYPE_INDEX])
                ->addIndex($setup->getIdxName($eventTable, ['created_at'], AdapterInterface::INDEX_TYPE_INDEX), ['created_at'], ['type' => AdapterInterface::INDEX_TYPE_INDEX]);
            $conn->createTable($table);
        }

        if (!$conn->isTableExists($blockTable)) {
            $table = $conn->newTable($blockTable)
                ->setComment('Blocked IPs')
                ->addColumn('block_id', Table::TYPE_INTEGER, null, ['identity' => true, 'unsigned' => true, 'nullable' => false, 'primary' => true], 'ID')
                ->addColumn('ip', Table::TYPE_TEXT, 45, ['nullable' => false], 'Blocked IP')
                ->addColumn('reason', Table::TYPE_TEXT, 255, ['nullable' => true], 'Reason')
                ->addColumn('created_at', Table::TYPE_TIMESTAMP, null, ['nullable' => false, 'default' => Table::TIMESTAMP_INIT], 'Created At (UTC)')
                ->addColumn('expires_at', Table::TYPE_TIMESTAMP, null, ['nullable' => true, 'default' => null], 'Expires At (UTC)')
                ->addIndex($setup->getIdxName($blockTable, ['ip'], AdapterInterface::INDEX_TYPE_UNIQUE), ['ip'], ['type' => AdapterInterface::INDEX_TYPE_UNIQUE])
                ->addIndex($setup->getIdxName($blockTable, ['expires_at'], AdapterInterface::INDEX_TYPE_INDEX), ['expires_at'], ['type' => AdapterInterface::INDEX_TYPE_INDEX]);
            $conn->createTable($table);
        }

        // 2) Kill the legacy conflicting index if it somehow exists
        try {
            if ($conn->isTableExists($blockTable) && $this->indexExists($conn, $blockTable, 'MERLIN_BLOCKED_IP_IP')) {
                $conn->dropIndex($blockTable, 'MERLIN_BLOCKED_IP_IP');
            }
        } catch (\Throwable $e) {
            // swallow; the goal is to avoid setup failures
        }

        $setup->endSetup();
    }

    private function indexExists($conn, string $table, string $index): bool
    {
        // Using describeTable indexes map is reliable across MySQL/MariaDB
        $indexes = $conn->getIndexList($table);
        return isset($indexes[$index]);
    }
}
