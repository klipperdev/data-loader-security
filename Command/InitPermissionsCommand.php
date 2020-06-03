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

use Klipper\Component\Console\Command\RequiredCommandsInterface;
use Klipper\Component\DataLoaderSecurity\Permission\YamlPermissionLoader;
use Klipper\Component\Resource\Domain\DomainManagerInterface;
use Klipper\Component\Security\Model\PermissionInterface;
use Klipper\Component\Security\Model\RoleInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Init the system permissions.
 *
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
class InitPermissionsCommand extends Command implements RequiredCommandsInterface
{
    private DomainManagerInterface $domainManager;

    private string $projectDir;

    public function __construct(DomainManagerInterface $domainManager, string $projectDir)
    {
        parent::__construct();

        $this->domainManager = $domainManager;
        $this->projectDir = $projectDir;
    }

    public function getRequiredCommands(): array
    {
        return [
            'init:roles',
        ];
    }

    protected function configure(): void
    {
        $this
            ->setName('init:permissions')
            ->setDescription('Init the system permissions')
        ;
    }

    /**
     * @throws \Exception
     */
    protected function execute(InputInterface $input, OutputInterface $output): void
    {
        $domainPermission = $this->domainManager->get(PermissionInterface::class);
        $domainRole = $this->domainManager->get(RoleInterface::class);
        $loader = new YamlPermissionLoader($domainPermission, $domainRole);
        $file = $this->projectDir.'/config/data/security_permissions.yaml';

        $loader->load($file);

        if ($loader->hasNewPermissions() || $loader->hasUpdatedPermissions() || $loader->hasUpdatedRoles()) {
            $output->writeln('  The system permissions have been initialized');
        } else {
            $output->writeln('  The system permissions are already up to date');
        }
    }
}
