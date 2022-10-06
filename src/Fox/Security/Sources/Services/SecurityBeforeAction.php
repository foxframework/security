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


use Fox\Core\Attribute\Autowire;
use Fox\Core\Attribute\Service;
use Fox\Core\Config\AppConfiguration;
use Fox\Core\Http\BeforeAction;
use Fox\Security\Attribute\Secured;
use Fox\Security\Config\FoxSecurityExtensionConfigInterface;
use Fox\Security\Http\ForbiddenException;
use Fox\Security\Sources\Services\Authorizer\AuthorizerResolver;
use ReflectionClass;

#[Service]
#[Autowire]
class SecurityBeforeAction implements BeforeAction
{
    private string $authorizerHandler;

    public function __construct(private IdentityProviderInterface $identityProvider,
                                private AppConfiguration $appConfiguration,
                                private AuthorizerResolver $authorizerResolver)
    {
        $this->authorizerHandler = $appConfiguration->foxSecurityGetAuthHandler();
    }

    public function handleBeforeAction(object $controller, string $method, mixed $body): void
    {
        $reflection = new ReflectionClass($controller);
        $securedAttribute = $reflection->getAttributes(Secured::class)[0] ?? null;
        if ($securedAttribute === null) {
            return;
        }

        $identity = $this->createIdentity();
        /** @var Secured $securedAttributeInstance */
        $securedAttributeInstance = $securedAttribute->newInstance();
        if ($this->identityProvider->isAllowed($identity, $securedAttributeInstance->role)) {
            return;
        }

        throw new ForbiddenException();
    }

    private function createIdentity(): Identity
    {
        $userData = $this->authorizerResolver->getAuthorizer($this->authorizerHandler)->authorizeRequest($this->appConfiguration);
        $identity = $this->identityProvider->createIdentity($userData);
        $this->identityProvider->setIdentity($identity);
        return $identity;
    }
}