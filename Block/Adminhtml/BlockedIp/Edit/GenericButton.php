<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Block\Adminhtml\BlockedIp\Edit;

use Magento\Backend\Block\Widget\Context;

abstract class GenericButton
{
    /** @var Context */
    protected $context;

    public function __construct(Context $context)
    {
        $this->context = $context;
    }

    protected function getUrl(string $route = '', array $params = []): string
    {
        return $this->context->getUrlBuilder()->getUrl($route, $params);
    }
}
