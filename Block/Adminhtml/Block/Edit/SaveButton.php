<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Block\Adminhtml\Block\Edit;

use Magento\Framework\View\Element\UiComponent\Control\ButtonProviderInterface;
use Magento\Ui\Component\Control\Container;

class SaveButton extends GenericButton implements ButtonProviderInterface
{
    public function getButtonData(): array
    {
        return [
            'label' => __('Save'),
            'class' => 'save primary',
            'data_attribute' => [
                'mage-init' => [
                    'buttonAdapter' => [
                        'actions' => [[
                            'targetName' => 'merlin_blocked_ip_form.merlin_blocked_ip_form',
                            'actionName' => 'save',
                            'params' => [false],
                        ]],
                    ],
                ],
            ],
            'class_name' => Container::SPLIT_BUTTON,
            'options' => $this->getOptions(),
            'sort_order' => 90,
        ];
    }

    private function getOptions(): array
    {
        return [[
            'id_hard' => 'save_and_continue',
            'label' => __('Save & Continue Edit'),
            'data_attribute' => [
                'mage-init' => [
                    'buttonAdapter' => [
                        'actions' => [[
                            'targetName' => 'merlin_blocked_ip_form.merlin_blocked_ip_form',
                            'actionName' => 'save',
                            'params' => [true, ['back' => 1]],
                        ]],
                    ],
                ],
            ],
            'sort_order' => 20,
        ]];
    }
}
