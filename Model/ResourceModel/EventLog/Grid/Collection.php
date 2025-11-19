<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\ResourceModel\EventLog\Grid;

use Magento\Framework\View\Element\UiComponent\DataProvider\Document;
use Magento\Framework\View\Element\UiComponent\DataProvider\SearchResult;
use Merlin\IntrusionDetection\Model\ResourceModel\EventLog as EventLogResource;

class Collection extends SearchResult
{
    protected function _construct()
    {
        $this->_init(Document::class, EventLogResource::class);
        $this->setMainTable('merlin_intrusion_event');

        // Example filter maps (optional, helpful for sorting/filter perf)
        $this->addFilterToMap('ip', 'main_table.ip');
        $this->addFilterToMap('created_at', 'main_table.created_at');
    }
}

