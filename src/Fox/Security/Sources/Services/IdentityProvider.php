<?php
/*
 * MIT License
 *
 * Copyright (c) 2021 Petr Ploner <petr@ploner.cz>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 */

namespace Fox\Security\Sources\Services;


use Fox\Core\Config\AppConfiguration;
use Fox\Core\Helpers\Globals;
use Fox\Security\Config\FoxSecurityExtensionConfigInterface;
use Fox\Security\Http\UnauthorizedException;

abstract class IdentityProvider implements IdentityProviderInterface
{
    private const FOX_SECURITY_IDENTITY = "foxSecurityIdentity";
    private array $roles;

    public function __construct(AppConfiguration $appConfiguration)
    {
        /** @var FoxSecurityExtensionConfigInterface $appConfiguration */
        $this->roles = $appConfiguration->foxSecurityGetRolePairs();
    }

    public final function setIdentity(Identity $identity): void
    {
        Globals::set(self::FOX_SECURITY_IDENTITY, $identity);
    }

    public final function getIdentity(): Identity
    {
        $i = Globals::get(self::FOX_SECURITY_IDENTITY);
        if ($i === null) {
            throw new UnauthorizedException();
        }
        return $i;
    }

    public function isAllowed(Identity $identity, string $minimumRole): bool
    {
        foreach ($identity->getRoles() as $role) {
            if ($this->matchesRoleOrParentRole($role, $minimumRole)) {
                return true;
            }
        }

        return false;
    }

    private function matchesRoleOrParentRole(string $role, string $minimumRole): bool
    {
        if (!array_key_exists($role, $this->roles)) {
            throw new ExpectedRoleDoesNotExistsException($role);
        }

        if (!array_key_exists($minimumRole, $this->roles)) {
            throw new ExpectedRoleDoesNotExistsException($minimumRole);
        }

        if ($role === $minimumRole) {
            return true;
        }

        $parent = $this->roles[$role];

        if (empty($parent)) {
            return false;
        }

        if (is_array($parent)) {
            foreach ($parent as $parentRole) {
                if ($this->matchesRoleOrParentRole($parentRole, $minimumRole)) {
                    return true;
                }
            }
            return false;
        }

        return $this->matchesRoleOrParentRole($parent, $minimumRole);
    }

    public abstract function createIdentity(array $authorizerData): Identity;

    public abstract function verifyCredentials(array $credentials): ?Identity;
}