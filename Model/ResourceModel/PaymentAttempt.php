<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\ResourceModel;

use Magento\Framework\Model\ResourceModel\Db\AbstractDb;

class PaymentAttempt extends AbstractDb
{
    protected function _construct(): void
    {
        $this->_init('merlin_payment_attempt', 'attempt_id');
    }
}
