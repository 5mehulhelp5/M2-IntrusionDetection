<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\ResourceModel\EventLog;

use Magento\Framework\Api\Search\AggregationInterface;
use Magento\Framework\Api\Search\SearchResultInterface;
use Magento\Framework\Model\ResourceModel\Db\Collection\AbstractCollection;

class Collection extends AbstractCollection implements SearchResultInterface {
    protected $_idFieldName = 'event_id';
    protected $aggregations;
    protected function _construct(){
        $this->_init(\Merlin\IntrusionDetection\Model\EventLog::class, \Merlin\IntrusionDetection\Model\ResourceModel\EventLog::class);
    }
    public function getAggregations(){ return $this->aggregations; }
    public function setAggregations($aggregations){ $this->aggregations=$aggregations; return $this; }
    public function getSearchCriteria(){ return null; }
    public function setSearchCriteria(\Magento\Framework\Api\SearchCriteriaInterface $searchCriteria = null){ return $this; }
    public function getTotalCount(){ return (int)$this->getSize(); }
    public function setTotalCount($totalCount){ return $this; }
    public function setItems(array $items = null){ return $this; }
}
