<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\Config\Source;

use Magento\Framework\Data\OptionSourceInterface;

/**
 * Provides a list of severity levels for detectors and blocking escalation.
 */
class Severity implements OptionSourceInterface
{
    /**
     * Return dropdown options for system.xml
     *
     * @return array<int, array<string, string>>
     */
    public function toOptionArray(): array
    {
        return [
            ['value' => 'low',      'label' => __('Low')],
            ['value' => 'medium',   'label' => __('Medium')],
            ['value' => 'high',     'label' => __('High')],
            ['value' => 'critical', 'label' => __('Critical')],
        ];
    }

    /**
     * Return simple associative array version if needed programmatically
     *
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return [
            'low'      => __('Low'),
            'medium'   => __('Medium'),
            'high'     => __('High'),
            'critical' => __('Critical'),
        ];
    }
}
