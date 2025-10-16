<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Ui\Component\Listing\Column;

use Magento\Framework\UrlInterface;
use Magento\Framework\View\Element\UiComponent\ContextInterface;
use Magento\Framework\View\Element\UiComponentFactory;
use Magento\Ui\Component\Listing\Columns\Column;

class BlockedIpActions extends Column
{
    private const URL_EDIT   = 'merlin_id/block/edit';
    private const URL_DELETE = 'merlin_id/block/delete';

    public function __construct(
        ContextInterface $context,
        UiComponentFactory $uiComponentFactory,
        private readonly UrlInterface $urlBuilder,
        array $components = [],
        array $data = []
    ) {
        parent::__construct($context, $uiComponentFactory, $components, $data);
    }

    public function prepareDataSource(array $dataSource): array
    {
        if (!isset($dataSource['data']['items'])) {
            return $dataSource;
        }

        $name = (string)$this->getData('name');

        foreach ($dataSource['data']['items'] as &$item) {
            $id = $item['block_id'] ?? null;
            if (!$id) {
                continue;
            }

            $ip = (string)($item['ip'] ?? '');

            $item[$name]['edit'] = [
                'href'  => $this->urlBuilder->getUrl(self::URL_EDIT,   ['block_id' => $id]),
                'label' => __('Edit'),
            ];

            // Label MUST be plain text. Put the IP only in confirm.
            $item[$name]['delete'] = [
                'href'    => $this->urlBuilder->getUrl(self::URL_DELETE, ['block_id' => $id]),
                'label'   => __('Delete'),
                'confirm' => [
                    'title'   => __('Delete "%1"', $ip),
                    'message' => __('Are you sure you want to delete the IP "%1"?', $ip),
                ],
                // Ensure POST with form_key, safer for admin deletes
                'post'    => true,
            ];
        }

        return $dataSource;
    }
}
