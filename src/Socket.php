<?php

/**
 * Socket helper class
 *
 * @package		EmailAuth
 * @author		Vladimir Osipov <vladimir.g.osipov@gmail.com>
 * @license		http://www.opensource.org/licenses/mit-license.php
 */

namespace EmailAuth;

class Socket
{
    /**
     * Tells if port is opened or not
     *
     * @param $host
     * @param int $port
     * @param int $timeout
     * @return bool
     */
    static public function pingPort($host, $port = 993, $timeout = 1)
    {
        if (!$fp = @fsockopen($host, $port, $errno, $errstr, $timeout))
        {
            return false;
        }

        fclose($fp);
        return true;
    }
}
