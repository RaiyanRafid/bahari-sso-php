<?php

namespace Bahari\Sso\Exception;

/** The account or admin session is no longer allowed (revoked, suspended, role removed, identity changed). End the local session. */
class AccessDeniedException extends BahariException {}
