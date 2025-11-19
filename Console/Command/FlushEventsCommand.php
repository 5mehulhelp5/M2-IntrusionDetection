<?php
declare(strict_types=1);

namespace Merlin\IntrusionDetection\Console\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Magento\Framework\App\ResourceConnection;

class FlushEventsCommand extends Command {
    private $rc;
    public function __construct(ResourceConnection $rc){ $this->rc=$rc; parent::__construct(); }
    protected function configure(){ $this->setName('merlin:ids:flush-events')->setDescription('Delete all intrusion events'); parent::configure(); }
    protected function execute(InputInterface $input, OutputInterface $output): int {
        $conn = $this->rc->getConnection(); $table = $this->rc->getTableName('merlin_intrusion_event'); $conn->truncateTable($table);
        $output->writeln('<info>Intrusion events flushed.</info>'); return Command::SUCCESS;
    }
}
