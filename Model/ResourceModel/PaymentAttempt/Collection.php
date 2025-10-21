<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\ResourceModel\PaymentAttempt;

use Magento\Framework\Model\ResourceModel\Db\Collection\AbstractCollection;
use Merlin\IntrusionDetection\Model\PaymentAttempt as Model;
use Merlin\IntrusionDetection\Model\ResourceModel\PaymentAttempt as ResourceModel;

class Collection extends AbstractCollection
{
    protected function _construct(): void
    {
        $this->_init(Model::class, ResourceModel::class);
    }
}
