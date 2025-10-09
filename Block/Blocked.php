<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Block;

use Magento\Framework\View\Element\Template;
use Merlin\IntrusionDetection\Model\Config;

class Blocked extends Template
{
    public function __construct(
        Template\Context $context,
        private readonly Config $config,
        array $data = []
    ) {
        parent::__construct($context, $data);
        // Set the page title only; do NOT touch response here.
        $this->pageConfig->getTitle()->set($this->getTitle());
    }

    public function getTitle(): string
    {
        return $this->config->blockedTitle();
    }

    public function getMessageHtml(): string
    {
        return $this->config->blockedMessage();
    }

    public function getContactEmail(): string
    {
        return $this->config->contactEmail();
    }

    public function getContactPhone(): string
    {
        return $this->config->contactPhone();
    }
}
