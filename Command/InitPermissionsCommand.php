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
use Klipper\Component\DataLoader\Command\AbstractDataLoaderCommand;
use Klipper\Component\DataLoader\DataLoaderInterface;
use Klipper\Component\DataLoaderSecurity\Permission\YamlPermissionLoader;
use Klipper\Component\Security\Model\PermissionInterface;
use Klipper\Component\Security\Model\RoleInterface;

/**
 * Init the system permissions.
 *
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
class InitPermissionsCommand extends AbstractDataLoaderCommand implements RequiredCommandsInterface
{
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

    protected function getDataLoader(): DataLoaderInterface
    {
        $domainPermission = $this->domainManager->get(PermissionInterface::class);
        $domainRole = $this->domainManager->get(RoleInterface::class);

        return new YamlPermissionLoader($domainPermission, $domainRole);
    }

    protected function getFindFileNames(): array
    {
        return [
            'security_permissions.yaml',
            'security_permissions_*.yaml',
        ];
    }

    protected function getEmptyMessage(): string
    {
        return 'No system permissions are defined';
    }

    protected function getInitializedMessage(): string
    {
        return 'The system permissions have been initialized';
    }

    protected function getUpToDateMessage(): string
    {
        return 'The system permissions are already up to date';
    }
}
