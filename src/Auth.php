<?php

namespace EmailAuth;

const STATUS_NO_LOGIN       = -1;       // No login attempt was done
const STATUS_OK             = 0;        // Successful login
const STATUS_OAUTH_NEEDED   = 1;        // Email provider will most probably require OAuth
const STATUS_WRONG_PASSWORD = 2;        // Wrong password
const STATUS_UNKNOWN        = 3;        // SMTP server was not found

class Auth
{
    private $email;
    private $password;

    public $status = STATUS_NO_LOGIN;

    public function login($email, $password)
    {
        $this->email = $email;
        $this->password = $password;
        $this->status = STATUS_UNKNOWN;

        $domain = explode('@', $email);

        if (!$mxServer = Dns::getTopMx($domain[1]))
        {
            // no MX record found, try direct login
            return $this->imapAuth('imap.' . $domain[1]);
        }

        // assure that it's not Google or some other
        $mxServerDomains = explode('.', $mxServer);

        $mxServerRoot = @implode('.', array_slice($mxServerDomains, -2, 2));

        if (in_array($mxServerRoot, ['google.com']))
        {
            $this->status = STATUS_OAUTH_NEEDED;

            // TODO: try direct login, maybe user has unlocked IMAP without OAuth

            return false;
        }

        // try opening port 993 on MX-server
        if ($this->pingPort($mxServer))
        {
            // IMAP server found => try to authenticate
            return $this->imapAuth($mxServer);
        }

        // last chance
        if ($this->pingPort('imap.' . $mxServerRoot))
        {
            return $this->imapAuth('imap.' . $mxServerRoot);
        }

        return false;
    }

    /**
     * @param $host
     * @param int $port
     * @return bool
     */
    private function pingPort($host, $port = 993)
    {
        if (!$fp = @fsockopen($host, $port, $errno, $errstr, 1))
        {
            return false;
        }

        fclose($fp);
        return true;
    }

    /**
     * @param $host
     * @param int $port
     * @return bool
     */
    private function imapAuth($host, $port = 993)
    {
        if (!$box = @imap_open('{' . $host . ':' . $port . '/imap/ssl/novalidate-cert/readonly}', $this->email, $this->password))
        {
            $this->status = STATUS_WRONG_PASSWORD;
            return false;
        }

        imap_close($box);
        $this->status = STATUS_OK;

        return true;
    }
}
