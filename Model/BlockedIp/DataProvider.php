<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model\BlockedIp;

use Magento\Ui\DataProvider\AbstractDataProvider;
use Merlin\IntrusionDetection\Model\ResourceModel\BlockedIp\CollectionFactory;

class DataProvider extends AbstractDataProvider
{
    protected $loadedData;

    public function __construct(
        string $name,
        string $primaryFieldName,
        string $requestFieldName,
        CollectionFactory $collectionFactory,
        array $meta = [],
        array $data = []
    ) {
        $this->collection = $collectionFactory->create();
        parent::__construct($name, $primaryFieldName, $requestFieldName, $meta, $data);
    }

    public function getData(): array
    {
        if (isset($this->loadedData)) {
            return $this->loadedData;
        }
        $this->loadedData = [];
foreach ($this->collection->getItems() as $item) {
    $data = $item->getData();
    // map DB -> form field so the textarea pre-fills on edit
    $data['comment'] = $data['reason'] ?? null;
    $this->loadedData[(int)$item->getId()] = $data;
}
        return $this->loadedData;
    }
}
