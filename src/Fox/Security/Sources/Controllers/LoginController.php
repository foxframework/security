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

namespace Fox\Security\Sources\Controllers;


use Fox\Core\Attribute\Autowire;
use Fox\Core\Attribute\Controller;
use Fox\Core\Attribute\Route;
use Fox\Core\Http\Response;
use Fox\Security\Sources\Services\AuthorizerService;

#[Controller]
#[Autowire]
#[Route("/login")]
class LoginController
{

    public function __construct(private AuthorizerService $authorizerService)
    {
    }

    public function post(array $credentials): Response
    {
        $responseBody = $this->authorizerService->authorize($credentials);
        return new Response(empty($responseBody) ? Response::HTTP_NO_CONTENT : Response::HTTP_OK, $responseBody);
    }
}