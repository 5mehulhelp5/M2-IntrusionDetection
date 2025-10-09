<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Adminhtml\Block;

use Magento\Backend\App\Action;
use Merlin\IntrusionDetection\Model\BlockedIpFactory;

class Save extends Action
{
    public const ADMIN_RESOURCE = 'Merlin_IntrusionDetection::blocks';

    /** @var BlockedIpFactory */
    private $factory;

    public function __construct(
        Action\Context $context,
        BlockedIpFactory $factory
    ) {
        parent::__construct($context);
        $this->factory = $factory;
    }

    public function execute()
    {
        $data = $this->getRequest()->getPostValue();
        $resultRedirect = $this->resultRedirectFactory->create();

        if (!$data) {
            return $resultRedirect->setPath('*/*/');
        }

        $id = (int)($data['block_id'] ?? 0);
        $model = $this->factory->create();
        if ($id) {
            $model->load($id);
        }

        $model->setData([
            'ip'         => (string)($data['ip'] ?? ''),
            'reason'     => $data['reason'] ?? null,
            'expires_at' => $data['expires_at'] ?? null,
        ]);

        try {
            $model->save();
            $this->messageManager->addSuccessMessage(__('Saved.'));

            if ($this->getRequest()->getParam('back')) {
                return $resultRedirect->setPath('*/*/edit', ['block_id' => (int)$model->getId()]);
            }
            return $resultRedirect->setPath('*/*/');
        } catch (\Throwable $e) {
            $this->messageManager->addErrorMessage(__('Error: %1', $e->getMessage()));
            return $resultRedirect->setPath('*/*/edit', ['block_id' => $id]);
        }
    }
}
