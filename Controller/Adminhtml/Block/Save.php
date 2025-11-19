<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Controller\Adminhtml\Block;

use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\Exception\LocalizedException;
use Magento\Framework\Stdlib\DateTime\TimezoneInterface;
use Merlin\IntrusionDetection\Model\BlockedIpFactory;
use Merlin\IntrusionDetection\Model\ResourceModel\BlockedIp\CollectionFactory as BlockedIpCollectionFactory;
use Psr\Log\LoggerInterface;

class Save extends Action implements HttpPostActionInterface
{
    public const ADMIN_RESOURCE = 'Merlin_IntrusionDetection::blocks';

    public function __construct(
        Context $context,
        private readonly BlockedIpFactory $blockedIpFactory,
        private readonly BlockedIpCollectionFactory $collectionFactory,
        private readonly TimezoneInterface $tz,
        private readonly LoggerInterface $logger
    ) {
        parent::__construct($context);
    }

    public function execute()
    {
        $resultRedirect = $this->resultRedirectFactory->create();
        $data = (array)$this->getRequest()->getPostValue();

        if (!$data) {
            $this->messageManager->addErrorMessage(__('No data to save.'));
            return $resultRedirect->setPath('*/*/index');
        }

        try {
            $id = (int)($data['block_id'] ?? 0);
            $ip = trim((string)($data['ip'] ?? ''));
            if ($ip === '') {
                throw new LocalizedException(__('IP address is required.'));
            }

            // Duplicate IP check (respect existing row when editing)
            $dup = $this->collectionFactory->create()
                ->addFieldToFilter('ip', $ip);
            if ($id) {
                $dup->addFieldToFilter('block_id', ['neq' => $id]);
            }
            if ($dup->getSize() > 0) {
                throw new LocalizedException(__('This IP is already blocked.'));
            }

            // Load or create model
            $model = $this->blockedIpFactory->create();
            if ($id) {
                $model->load($id);
                if (!$model->getId()) {
                    throw new LocalizedException(__('This record no longer exists.'));
                }
            }

            // Date normalization for TIMESTAMP column
            $expires = null;
            $expiresRaw = trim((string)($data['expires_at'] ?? ''));
            if ($expiresRaw !== '') {
                // Accept common formats; normalise to Y-m-d H:i:s in store timezone
                try {
                    $dt = new \DateTime($expiresRaw);
                } catch (\Throwable $e) {
                    // Try strict Y-m-d (UI date with dateFormat yyyy-MM-dd)
                    $dt = \DateTime::createFromFormat('Y-m-d', $expiresRaw) ?: null;
                }
                if ($dt) {
                    // convert to store timezone, then format as timestamp string
                    $tzDt = $this->tz->convertConfigTimeToUtc($dt->format('Y-m-d H:i:s'));
                    $expires = (new \DateTime($tzDt))->format('Y-m-d H:i:s');
                }
            }

            // Map form -> DB
            $model->setData('ip', $ip);
            $model->setData('reason', $data['comment'] ?? null);
            $model->setData('expires_at', $expires);

            $model->save();

            $this->messageManager->addSuccessMessage(__('IP saved.'));
            if ($this->getRequest()->getParam('back')) {
                return $resultRedirect->setPath('*/*/edit', ['block_id' => (int)$model->getId()]);
            }
            return $resultRedirect->setPath('*/*/index');

        } catch (LocalizedException $e) {
            $this->messageManager->addErrorMessage($e->getMessage());
            $this->logger->error('BlockedIp save LocalizedException: ' . $e->getMessage());
        } catch (\Throwable $e) {
            $this->messageManager->addErrorMessage(__('Something went wrong while saving.'));
            $this->logger->error('BlockedIp save error: ' . $e->getMessage(), ['trace' => $e->getTraceAsString()]);
        }

        $this->_getSession()->setFormData($data);
        return $resultRedirect->setPath('*/*/edit', ['block_id' => (int)($data['block_id'] ?? 0)]);
    }
}
