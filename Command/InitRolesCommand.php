<?php

/*
 * This file is part of the Klipper package.
 *
 * (c) François Pluchino <francois.pluchino@klipper.dev>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Klipper\Component\DataLoaderSecurity\Command;

use Klipper\Component\DataLoader\Entity\YamlUniqueEntityLoader;
use Klipper\Component\Resource\Domain\DomainManagerInterface;
use Klipper\Component\Security\Model\RoleInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Init the system roles.
 *
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
class InitRolesCommand extends Command
{
    private DomainManagerInterface $domainManager;

    private string $projectDir;

    public function __construct(DomainManagerInterface $domainManager, string $projectDir)
    {
        parent::__construct();

        $this->domainManager = $domainManager;
        $this->projectDir = $projectDir;
    }

    protected function configure(): void
    {
        $this
            ->setName('init:roles')
            ->setDescription('Init the system roles')
        ;
    }

    /**
     * @throws \Exception
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $domain = $this->domainManager->get(RoleInterface::class);
        $loader = new YamlUniqueEntityLoader($domain);
        $file = $this->projectDir.'/config/data/security_roles.yaml';

        $loader->load($file);

        if ($loader->hasNewEntities() || $loader->hasUpdatedEntities()) {
            $output->writeln('  The system roles have been initialized');
        } else {
            $output->writeln('  The system roles are already up to date');
        }

        return 0;
    }
}
