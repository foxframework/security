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
use Fox\Security\Config\FoxSecurityExtensionConfigInterface;
use Fox\Security\Sources\Services\Authorizer\AuthorizerResolver;

#[Service]
#[Autowire]
class AuthorizerService
{
    private string $authorizerHandler;
    private FoxSecurityExtensionConfigInterface $config;

    public function __construct(private AuthorizerResolver $authorizerResolver,
                                private IdentityProviderInterface $identityProvider,
                                AppConfiguration $appConfiguration)
    {
        /** @var FoxSecurityExtensionConfigInterface $appConfiguration */
        $this->authorizerHandler = $appConfiguration->foxSecurityGetAuthHandler();
        $this->config = $appConfiguration;
    }

    public function authorize(array $credentials): mixed
    {
        return $this->authorizerResolver->getAuthorizer($this->authorizerHandler)->doAuthorization($credentials, $this->identityProvider, $this->config);
    }

    public function reAuthorize(array $credentials): mixed
    {
        return $this->authorizerResolver->getAuthorizer($this->authorizerHandler)->doReAuthorization($credentials, $this->identityProvider, $this->config);
    }


}