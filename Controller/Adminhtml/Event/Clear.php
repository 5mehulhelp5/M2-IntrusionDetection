<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Adminhtml\Event;

use Magento\Backend\App\Action;
use Magento\Framework\App\ResourceConnection;

class Clear extends Action
{
    public const ADMIN_RESOURCE = 'Merlin_IntrusionDetection::events';

    /** @var ResourceConnection */
    private $rc;

    public function __construct(
        Action\Context $context,
        ResourceConnection $rc
    ) {
        parent::__construct($context);
        $this->rc = $rc;
    }

    public function execute()
    {
        $conn = $this->rc->getConnection();
        $conn->truncateTable($this->rc->getTableName('merlin_intrusion_event'));

        $this->messageManager->addSuccessMessage(__('Intrusion log cleared.'));

        // Use parent-provided factory; do NOT redeclare as promoted/readonly property
        return $this->resultRedirectFactory->create()->setPath('*/*/');
    }
}
