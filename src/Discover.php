<?php

/**
 * Discover IMAP or/and SMTP settings
 *
 * @package		EmailAuth
 * @author		Vladimir Osipov <vladimir.g.osipov@gmail.com>
 * @license		http://www.opensource.org/licenses/mit-license.php
 */

namespace EmailAuth;

class Discover
{
    /**
     * Discovers IMAP settings for an email
     *
     * @param $email
     * @return array|null
     * @throws \Exception
     */
    public function imap($email)
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL))
        {
            throw new \Exception('Not a valid email');
        }

        $host = null;
        $domain = explode('@', $email);

        if ($port = Socket::pingPort('imap.' . $domain[1], [993, 143]))
        {
            $host = 'imap.' . $domain[1];
        }
        elseif ($mxServer = Dns::getTopMx($domain[1]))
        {
            $mxServerDomains = explode('.', $mxServer);
            $mxServerRoot = @implode('.', array_slice($mxServerDomains, -2, 2));

            if ($port = Socket::pingPort($mxServer, [993, 143]))
            {
                $host = $mxServer;
            }
            else if ($port = Socket::pingPort('imap.' . $mxServerRoot, [993, 143]))
            {
                $host = 'imap.' . $mxServerRoot;
            }
        }

        return $host ? array
        (
            'host'       => $host,
            'port'       => $port,
            'encryption' => 993 == $port ? 'ssl' : null,
        ) : null;
    }

    /**
     * Discovers SMTP settings for an email
     *
     * @param $email
     * @return array|null
     * @throws \Exception
     */
    public function smtp($email)
    {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL))
        {
            throw new \Exception('Not a valid email');
        }

        $host = null;
        $domain = explode('@', $email);

        if ($port = Socket::pingPort('smtp.' . $domain[1], [465, 587, 25]))
        {
            $host = 'smtp.' . $domain[1];
        }
        elseif ($mxServer = Dns::getTopMx($domain[1]))
        {
            $mxServerDomains = explode('.', $mxServer);
            $mxServerRoot = @implode('.', array_slice($mxServerDomains, -2, 2));

            if ($port = Socket::pingPort($mxServer, [465, 587, 25]))
            {
                $host = $mxServer;
            }
            else if ($port = Socket::pingPort('smtp.' . $mxServerRoot, [465, 587, 25]))
            {
                $host = 'smtp.' . $mxServerRoot;
            }
        }

        $encTypes =
        [
            25  => null,
            465 => 'ssl',
            587 => 'tls',
        ];

        return $host ? array
        (
            'host'       => $host,
            'port'       => $port,
            'encryption' => @$encTypes[$port] ?: null,
        ) : null;
    }
}
