<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Block\Adminhtml\Block\Index;

use Magento\Framework\View\Element\UiComponent\Control\ButtonProviderInterface;
use Merlin\IntrusionDetection\Block\Adminhtml\Block\Edit\GenericButton;

class AddButton extends GenericButton implements ButtonProviderInterface
{
    public function getButtonData(): array
    {
        return [
            'label' => __('Add New Blocked IP'),
            'class' => 'primary',
            'on_click' => sprintf("location.href = '%s';", $this->getUrl('*/*/new')),
            'sort_order' => 10,
        ];
    }
}
