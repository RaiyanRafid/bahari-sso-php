<?php

namespace Bahari\Sso\Exception;

use Bahari\Sso\Http\Response;

class HttpException extends BahariException
{
    public function __construct(public readonly Response $response, string $url)
    {
        parent::__construct('Bahari Accounts answered '.$response->status.' for '.parse_url($url, PHP_URL_PATH).'.');
    }
}
