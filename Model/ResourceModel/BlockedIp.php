<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\ResourceModel;

use Magento\Framework\Model\ResourceModel\Db\AbstractDb;

class BlockedIp extends AbstractDb {
    protected function _construct(){ $this->_init('merlin_blocked_ip','block_id'); }
}
