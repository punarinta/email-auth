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
     * @return null|string
     */
    public function imap($email)
    {
        $host = null;
        $domain = explode('@', $email);

        if (Socket::pingPort('imap.' . $domain[1]))
        {
            $host = 'imap.' . $domain[1];
        }
        elseif ($mxServer = Dns::getTopMx($domain[1]))
        {
            $mxServerDomains = explode('.', $mxServer);
            $mxServerRoot = @implode('.', array_slice($mxServerDomains, -2, 2));

            if (Socket::pingPort($mxServer))
            {
                $host = $mxServer;
            }
            else if (Socket::pingPort('imap.' . $mxServerRoot))
            {
                $host = 'imap.' . $mxServerRoot;
            }
        }

        return array
        (
            'host' => $host,
            'port' => 993,
        );
    }
}
