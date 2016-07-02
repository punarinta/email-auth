<?php

/**
 * Authentication via email class
 *
 * @package		EmailAuth
 * @author		Vladimir Osipov <vladimir.g.osipov@gmail.com>
 * @license		http://www.opensource.org/licenses/mit-license.php
 */

namespace EmailAuth;

class Auth
{
    const STATUS_NO_LOGIN       = -1;       // No login attempt was done
    const STATUS_OK             = 0;        // Successful login
    const STATUS_OAUTH_NEEDED   = 1;        // Email provider will most probably require OAuth
    const STATUS_WRONG_PASSWORD = 2;        // Wrong password
    const STATUS_UNKNOWN        = 3;        // IMAP server was not found

    private $email;
    private $password;
    private $config;

    public $status = self::STATUS_NO_LOGIN;

    /**
     * Auth constructor.
     * @param array $cfg
     */
    public function __construct($cfg = [])
    {
        $this->config = new \stdClass();
        $this->config->tryRestricted = isset ($cfg['tryRestricted']) ? $cfg['tryRestricted'] : false;
        $this->config->pingTimeout = isset ($cfg['pingTimeout']) ? $cfg['pingTimeout'] : 1;
    }

    /**
     * Tries to find an auth server and login
     *
     * @param $email
     * @param $password
     * @return bool
     * @throws \Exception
     */
    public function login($email, $password)
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL))
        {
            throw new \Exception('Not a valid email');
        }

        $this->email = $email;
        $this->password = $password;
        $this->status = self::STATUS_UNKNOWN;

        $discover = new Discover;
        if ($cfg = $discover->imap($email))
        {
            if ($discover->mxServerRoot)
            {
                // assure that it's not Google or some other
                if (in_array($discover->mxServerRoot, ['google.com', 'outlook.com']))
                {
                    if ($this->config->tryRestricted)
                    {
                        return $this->imapAuth('imap.' . $discover->mxServerRoot);
                    }

                    $this->status = self::STATUS_OAUTH_NEEDED;
                    return false;
                }
            }

            return $this->imapAuth($cfg['host'], $cfg['port']);
        }
        else
        {
            $domain = explode('@', $email);
            return $this->imapAuth('imap.' . $domain[1]);
        }
    }

    /**
     * Tries to authenticate by logging to an IMAP server
     *
     * @param $host
     * @param int $port
     * @return bool
     */
    private function imapAuth($host, $port = 993)
    {
        if (!$box = @imap_open('{' . $host . ':' . $port . '/imap/ssl/novalidate-cert/readonly}', $this->email, $this->password))
        {
            $this->status = self::STATUS_WRONG_PASSWORD;
            return false;
        }

        imap_close($box);
        $this->status = self::STATUS_OK;

        return true;
    }
}
