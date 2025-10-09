<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Adminhtml\Block;

use Magento\Backend\App\Action;
use Magento\Framework\App\ResourceConnection;

class Delete extends Action
{
    public const ADMIN_RESOURCE = 'Merlin_IntrusionDetection::blocks';

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
        $id = (int)$this->getRequest()->getParam('block_id');
        if ($id) {
            $this->rc->getConnection()->delete(
                $this->rc->getTableName('merlin_blocked_ip'),
                ['block_id = ?' => $id]
            );
            $this->messageManager->addSuccessMessage(__('IP removed.'));
        } else {
            $this->messageManager->addErrorMessage(__('Missing ID.'));
        }

        return $this->resultRedirectFactory->create()->setPath('*/*/');
    }
}
