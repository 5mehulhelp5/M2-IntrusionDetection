<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model;

use Magento\Framework\Model\AbstractModel;

class PaymentAttempt extends AbstractModel
{
    protected function _construct(): void
    {
        $this->_init(\Merlin\IntrusionDetection\Model\ResourceModel\PaymentAttempt::class);
    }
}
