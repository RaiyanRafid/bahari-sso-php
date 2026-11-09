<?php

namespace Bahari\Sso\Exception;

/** A token failed signature, issuer, audience, nonce or lifetime checks. */
class InvalidTokenException extends BahariException {}
