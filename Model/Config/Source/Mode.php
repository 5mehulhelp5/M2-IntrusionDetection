<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Config\Source;

use Magento\Framework\Option\ArrayInterface;

class Mode implements ArrayInterface {
    public function toOptionArray() {
        return [
            ['value' => 'detect', 'label' => __('Detect (log only)')],
            ['value' => 'block', 'label' => __('Block (403 & auto-block)')],
        ];
    }
}
