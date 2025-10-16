<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\ResourceModel\BlockedIp\Grid;

use Magento\Framework\Data\Collection\Db\FetchStrategyInterface;
use Magento\Framework\Data\Collection\EntityFactoryInterface;
use Magento\Framework\Event\ManagerInterface;
use Magento\Framework\Model\ResourceModel\Db\AbstractDb;
use Magento\Framework\View\Element\UiComponent\DataProvider\SearchResult;
use Psr\Log\LoggerInterface;

class Collection extends SearchResult
{
    protected $_idFieldName = 'block_id';

    public function __construct(
        EntityFactoryInterface $entityFactory,
        LoggerInterface $logger,
        FetchStrategyInterface $fetchStrategy,
        ManagerInterface $eventManager,
        $mainTable = 'merlin_blocked_ip',
        $resourceModel = \Merlin\IntrusionDetection\Model\ResourceModel\BlockedIp::class
    ) {
        parent::__construct($entityFactory, $logger, $fetchStrategy, $eventManager, $mainTable, $resourceModel);
    }

    protected function _initSelect()
    {
        parent::_initSelect();
        
        // Add filter maps for better column handling
        $this->addFilterToMap('block_id', 'main_table.block_id');
        $this->addFilterToMap('ip', 'main_table.ip');
        $this->addFilterToMap('created_at', 'main_table.created_at');
        $this->addFilterToMap('expires_at', 'main_table.expires_at');
        
        return $this;
    }
}
