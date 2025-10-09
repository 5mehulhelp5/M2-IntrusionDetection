<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\ResourceModel;

use Magento\Framework\Model\ResourceModel\Db\AbstractDb;

class EventLog extends AbstractDb {
    protected function _construct(){ $this->_init('merlin_intrusion_event','event_id'); }
}
