<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Block\Adminhtml\Buttons\Grid;

use Magento\Backend\Block\Widget\Context;
use Magento\Framework\View\Element\UiComponent\Control\ButtonProviderInterface;

class AddBlockedIp implements ButtonProviderInterface
{
    /** @var Context */
    private $context;

    public function __construct(Context $context)
    {
        $this->context = $context;
    }

    public function getButtonData(): array
    {
        return [
            'label'      => __('Add Blocked IP'),
            'class'      => 'primary',
            'on_click'   => sprintf("location.href = '%s';", $this->context->getUrlBuilder()->getUrl('merlin_id/block/new')),
            'sort_order' => 10
        ];
    }
}
