<?php
/**
 * Merlin Intrusion Detection - Blocked IP Model
 */

declare(strict_types=1);

namespace Merlin\IntrusionDetection\Model;

use Magento\Framework\Model\AbstractModel;
use Magento\Framework\DataObject\IdentityInterface;
use Merlin\IntrusionDetection\Model\ResourceModel\BlockedIp as BlockedIpResource;

/**
 * @method int|null getId()
 * @method $this setId(int $id)
 * @method string|null getIp()
 * @method $this setIp(string $ip)
 * @method string|null getReason()
 * @method $this setReason(?string $reason)
 * @method string|null getCreatedAt()
 * @method $this setCreatedAt(string $datetime)
 * @method string|null getExpiresAt()
 * @method $this setExpiresAt(?string $datetime)
 */
class BlockedIp extends AbstractModel implements IdentityInterface
{
    /**#@+
     * DB field names
     */
    public const ID         = 'block_id';
    public const IP         = 'ip';
    public const REASON     = 'reason';
    public const CREATED_AT = 'created_at';
    public const EXPIRES_AT = 'expires_at';
    /**#@-*/

    /** Cache tag */
    public const CACHE_TAG = 'merlin_blocked_ip';

    /** @var string */
    protected $_cacheTag = self::CACHE_TAG;

    /** @var string */
    protected $_eventPrefix = 'merlin_blocked_ip';

    /**
     * Define resource model
     */
    protected function _construct(): void
    {
        $this->_init(BlockedIpResource::class);
    }

    /**
     * Identities for FPC/Blocks cache invalidation
     *
     * @return string[]
     */
    public function getIdentities(): array
    {
        $id = $this->getId();
        return [self::CACHE_TAG . '_' . ($id !== null ? $id : 'new')];
    }

    /**
     * Convenience getters/setters with constants (optional helpers)
     */

    public function getBlockId(): ?int
    {
        $id = $this->getData(self::ID);
        return $id !== null ? (int)$id : null;
    }

    public function setBlockId(int $id): self
    {
        return $this->setData(self::ID, $id);
    }

    public function getIp(): ?string
    {
        $val = $this->getData(self::IP);
        return $val !== null ? (string)$val : null;
    }

    public function setIp(string $ip): self
    {
        return $this->setData(self::IP, $ip);
    }

    public function getReason(): ?string
    {
        $val = $this->getData(self::REASON);
        return $val !== null ? (string)$val : null;
    }

    public function setReason(?string $reason): self
    {
        return $this->setData(self::REASON, $reason);
    }

    public function getCreatedAt(): ?string
    {
        $val = $this->getData(self::CREATED_AT);
        return $val !== null ? (string)$val : null;
    }

    public function setCreatedAt(string $datetime): self
    {
        return $this->setData(self::CREATED_AT, $datetime);
    }

    public function getExpiresAt(): ?string
    {
        $val = $this->getData(self::EXPIRES_AT);
        return $val !== null ? (string)$val : null;
    }

    public function setExpiresAt(?string $datetime): self
    {
        return $this->setData(self::EXPIRES_AT, $datetime);
    }
}
