<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Block\Adminhtml\Block\Edit;

use Magento\Backend\Block\Widget\Context;

abstract class GenericButton
{
    public function __construct(protected Context $context) {}

    protected function getUrl(string $route = '', array $params = []): string
    {
        return $this->context->getUrlBuilder()->getUrl($route, $params);
    }
}
