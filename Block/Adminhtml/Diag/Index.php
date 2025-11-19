<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Block\Adminhtml\Diag;

use Magento\Backend\Block\Template;
use Magento\Framework\Registry;

class Index extends Template
{
    public function __construct(
        Template\Context $context,
        private readonly Registry $registry,
        array $data = []
    ) {
        parent::__construct($context, $data);
    }

    public function getPostUrl(): string
    {
        return $this->getUrl('merlinids/diag/index');
    }

    public function getResults(): array
    {
        return (array)($this->registry->registry('merlin_ids_diag_results') ?? []);
    }

    public function getFormKey(): string
    {
        return $this->getFormKeyHtml();
    }
}
