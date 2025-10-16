<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Ui\DataProvider\BlockedIp;

use Magento\Ui\DataProvider\AbstractDataProvider;
use Merlin\IntrusionDetection\Model\ResourceModel\BlockedIp\CollectionFactory;

class ListingDataProvider extends AbstractDataProvider
{
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
}
