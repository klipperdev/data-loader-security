<?php

/*
 * This file is part of the Klipper package.
 *
 * (c) François Pluchino <francois.pluchino@klipper.dev>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Klipper\Component\DataLoaderSecurity\Permission;

use Klipper\Component\DataLoader\DataLoaderInterface;
use Klipper\Component\DataLoader\Exception\ConsoleResourceException;
use Klipper\Component\DataLoader\Exception\RuntimeException;
use Klipper\Component\Model\Traits\LabelableInterface;
use Klipper\Component\Resource\Domain\DomainInterface;
use Klipper\Component\Resource\ResourceList;
use Klipper\Component\Resource\ResourceListInterface;
use Klipper\Component\Security\Model\PermissionInterface;
use Klipper\Component\Security\Model\RoleInterface;
use Klipper\Component\Security\Permission\PermissionUtils;

/**
 * @author François Pluchino <francois.pluchino@klipper.dev>
 */
abstract class BasePermissionLoader implements DataLoaderInterface
{
    protected DomainInterface $domainPermission;

    protected DomainInterface $domainRole;

    protected PermissionConfiguration $config;

    protected PermissionProcessor $processor;

    protected bool $hasNewPermissions = false;

    protected bool $hasUpdatedPermissions = false;

    protected bool $hasUpdatedRoles = false;

    /**
     * @param DomainInterface              $domainPermission The resource domain of permission
     * @param DomainInterface              $domainRole       The resource domain of role
     * @param null|PermissionConfiguration $config           The permission configuration
     * @param null|PermissionProcessor     $processor        The permission processor
     */
    public function __construct(
        DomainInterface $domainPermission,
        DomainInterface $domainRole,
        ?PermissionConfiguration $config = null,
        ?PermissionProcessor $processor = null
    ) {
        $this->domainPermission = $domainPermission;
        $this->domainRole = $domainRole;
        $this->config = $config ?? new PermissionConfiguration();
        $this->processor = $processor ?? new PermissionProcessor();
    }

    public function load($resource): ResourceListInterface
    {
        $content = $this->loadContent($resource);
        $config = $this->processor->process($this->config, [$content]);

        return $this->doLoad($config);
    }

    /**
     * Check if the new permissions are loaded.
     */
    public function hasNewPermissions(): bool
    {
        return $this->hasNewPermissions;
    }

    /**
     * Check if the permissions are updated.
     */
    public function hasUpdatedPermissions(): bool
    {
        return $this->hasUpdatedPermissions;
    }

    /**
     * Check if the roles are updated.
     */
    public function hasUpdatedRoles(): bool
    {
        return $this->hasUpdatedRoles;
    }

    /**
     * Load the resource content.
     *
     * @param mixed $resource The resource
     */
    abstract protected function loadContent($resource): array;

    /**
     * Action to load the config of permissions in doctrine.
     *
     * @param array $config The config of permissions
     */
    private function doLoad(array $config): ResourceListInterface
    {
        $roles = $this->getUsedRoles($config);
        $permissions = $this->getPermissions();

        $fullPermissions = $this->loadPermissions($config, $permissions);

        return $this->loadRolePermissions($config, $fullPermissions, $roles);
    }

    /**
     * Load the relation between the permissions and roles in database.
     *
     * @param array           $config      The config
     * @param array           $permissions The permission map
     * @param RoleInterface[] $roles       The used roles
     */
    private function loadRolePermissions(array $config, array $permissions, array $roles): ResourceListInterface
    {
        $updates = [];

        $this->addRolePermission($config, $permissions, $roles, $updates);

        foreach ($config['permission_classes'] as $class => $classConfig) {
            $this->addRolePermission($classConfig, $permissions, $roles, $updates, $class);

            foreach ($classConfig['fields'] as $field => $fieldConfig) {
                $this->addRolePermission($fieldConfig, $permissions, $roles, $updates, $class, $field);
            }
        }

        if (!empty($updates)) {
            return $this->domainRole->updates(array_values($updates));
        }

        return new ResourceList();
    }

    /**
     * Add the permission instance in the list of upsert and add or update the values.
     *
     * @param array                 $config      The config
     * @param PermissionInterface[] $permissions The permission map
     * @param RoleInterface[]       $roles       The roles
     * @param RoleInterface[]       $updates     The roles must be updated
     * @param null|string           $class       The class name
     * @param null|string           $field       The field name
     */
    private function addRolePermission(array $config, array $permissions, array $roles, array &$updates, ?string $class = null, ?string $field = null): void
    {
        foreach ($config['permissions'] as $operation => $permConfig) {
            if (isset($permConfig['attached_roles']) && !empty($permConfig['attached_roles'])) {
                $id = $this->createCacheId($operation, $class, $field);
                $perm = $permissions[$id];

                foreach ($permConfig['attached_roles'] as $roleName) {
                    $role = $roles[$roleName];

                    if (!$role->hasPermission($perm)) {
                        $role->addPermission($perm);
                        $updates[$role->getName()] = $role;
                        $this->hasUpdatedRoles = true;
                    }
                }
            }
        }
    }

    /**
     * Load the permissions in database.
     *
     * @param array $config      The config
     * @param array $permissions The permission map
     *
     * @return PermissionInterface[]
     */
    private function loadPermissions(array $config, array $permissions): array
    {
        $fullPermissions = [];
        $upserts = [];

        $fullPermissions[] = $this->addPermission($config, $permissions, $upserts);

        foreach ($config['permission_classes'] as $class => $classConfig) {
            $fullPermissions[] = $this->addPermission($classConfig, $permissions, $upserts, $class);

            foreach ($classConfig['fields'] as $field => $fieldConfig) {
                $fullPermissions[] = $this->addPermission($fieldConfig, $permissions, $upserts, $class, $field);
            }
        }

        if (!empty($upserts)) {
            $res = $this->domainPermission->upserts($upserts);

            if ($res->hasErrors()) {
                throw new ConsoleResourceException($res, 'operation');
            }
        }

        return \count($fullPermissions) > 0 ? array_merge(...$fullPermissions) : $fullPermissions;
    }

    /**
     * Add the permission instance in the list of upsert and add or update the values.
     *
     * @param array                 $config      The config
     * @param array                 $permissions The permission map
     * @param PermissionInterface[] $upserts     The permissions must be created or updated
     * @param null|string           $class       The class name
     * @param null|string           $field       The field name
     *
     * @return PermissionInterface[]
     */
    private function addPermission(array $config, array $permissions, array &$upserts, ?string $class = null, ?string $field = null): array
    {
        $fullPermissions = [];

        foreach ($config['permissions'] as $operation => $permConfig) {
            $pClass = PermissionUtils::getMapAction($class);
            $pField = PermissionUtils::getMapAction($field);

            if (!isset($permissions[$pClass][$pField][$operation])) {
                /** @var PermissionInterface $perm */
                $perm = $this->domainPermission->newInstance();
                $perm->setOperation($operation);
                $perm->setClass($class);
                $perm->setField($field);
                $this->injectValues($perm, $permConfig);
                $upserts[] = $perm;
                $this->hasNewPermissions = true;
            } else {
                $perm = $permissions[$pClass][$pField][$operation];
                $res = $this->injectValues($perm, $permConfig);
                $upserts[] = $perm;

                if ($res) {
                    $this->hasUpdatedPermissions = true;
                }
            }

            $fullPermissions[$this->getCacheId($perm)] = $perm;
        }

        return $fullPermissions;
    }

    /**
     * Inject the config values in the permission.
     *
     * @param PermissionInterface $permission The permission
     * @param array               $config     The config
     */
    private function injectValues(PermissionInterface $permission, array $config): bool
    {
        $updated = false;

        if (implode(':', $permission->getContexts()) !== implode(':', $config['contexts'])) {
            $permission->setContexts($config['contexts']);
            $updated = true;
        }

        if ($permission instanceof LabelableInterface && $permission->getLabel() !== $config['label']) {
            $permission->setLabel($config['label']);
            $updated = true;
        }

        if (method_exists($permission, 'getDetailLabel') && method_exists($permission, 'setDetailLabel')
                && $permission->getDetailLabel() !== $config['detail_label']) {
            $permission->setDetailLabel($config['detail_label']);
            $updated = true;
        }

        if (method_exists($permission, 'getTranslationDomain') && method_exists($permission, 'setTranslationDomain')
                && $permission->getTranslationDomain() !== $config['translation_domain']) {
            $permission->setTranslationDomain($config['translation_domain']);
            $updated = true;
        }

        return $updated;
    }

    /**
     * Get the map of permissions.
     */
    private function getPermissions(): array
    {
        /** @var PermissionInterface[] $permissions */
        $permissions = $this->domainPermission->getRepository()->findAll();
        $cache = [];

        foreach ($permissions as $perm) {
            $class = PermissionUtils::getMapAction($perm->getClass());
            $field = PermissionUtils::getMapAction($perm->getField());
            $cache[$class][$field][$perm->getOperation()] = $perm;
        }

        return $cache;
    }

    /**
     * Get the used roles.
     *
     * @param array $config The config
     *
     * @return RoleInterface[]
     */
    private function getUsedRoles(array $config): array
    {
        $usedRoles = $this->findUsedRoles($config);
        $mapRoles = [];
        /** @var RoleInterface[] $roles */
        $roles = [];

        if (!empty($usedRoles)) {
            $roles = $this->domainRole->getRepository()->findBy([
                'organization' => null,
                'name' => $usedRoles,
            ]);
        }

        $this->validateUsedRoles($roles, $usedRoles);

        foreach ($roles as $role) {
            $mapRoles[$role->getName()] = $role;
        }

        return $mapRoles;
    }

    /**
     * Validate the used roles.
     *
     * @param RoleInterface[] $roles     The roles
     * @param string[]        $usedRoles The used roles in config
     */
    private function validateUsedRoles(array $roles, array $usedRoles): void
    {
        $names = [];
        $missing = [];

        foreach ($roles as $role) {
            $names[] = $role->getName();
        }

        foreach ($usedRoles as $usedRole) {
            if (!\in_array($usedRole, $names, true)) {
                $missing[] = $usedRole;
            }
        }

        if (!empty($missing)) {
            $msg = 'The roles "%s" are required, but does not exists in database';

            throw new RuntimeException(sprintf($msg, implode('", "', $missing)));
        }
    }

    /**
     * Find the used roles.
     *
     * @param array $config The config
     *
     * @return string[]
     */
    private function findUsedRoles(array $config): array
    {
        $roles = [];
        $roles[] = $this->doFindUsedRoles($config);

        foreach ($config['permission_classes'] as $classConfig) {
            $roles[] = $this->doFindUsedRoles($classConfig);

            foreach ($classConfig['fields'] as $fieldConfig) {
                $roles[] = $this->doFindUsedRoles($fieldConfig);
            }
        }

        return \count($roles) > 0 ? array_merge(...$roles) : $roles;
    }

    /**
     * Action to find the used roles.
     *
     * @param array $config The config
     *
     * @return string[]
     */
    private function doFindUsedRoles(array $config): array
    {
        $roles = [];

        foreach ($config['permissions'] as $permConfig) {
            if (isset($permConfig['attached_roles']) && !empty($permConfig['attached_roles'])) {
                $roles[] = $permConfig['attached_roles'];
            }
        }

        return \count($roles) > 0 ? array_merge(...$roles) : $roles;
    }

    /**
     * Get the permission cache id.
     *
     * @param PermissionInterface $permission The permission
     */
    private function getCacheId(PermissionInterface $permission): string
    {
        return $permission->getOperation().':'.$permission->getClass().':'.$permission->getField();
    }

    /**
     * Create the permission cache id.
     *
     * @param string      $operation The permission operation
     * @param null|string $class     The class name
     * @param null|string $field     The field name
     */
    private function createCacheId(string $operation, ?string $class = null, ?string $field = null): string
    {
        return $operation.':'.$class.':'.$field;
    }
}
