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
     * Tells if port (or one of the ports) is opened or not
     *
     * @param $host
     * @param array $ports
     * @param int $timeout
     * @return bool|mixed
     */
    static public function pingPort($host, $ports = [993], $timeout = 1)
    {
        if (!is_array($ports))
        {
            $ports = [$ports];
        }

        foreach ($ports as $port)
        {
            if ($fp = @fsockopen($host, $port, $errno, $errstr, $timeout))
            {
                fclose($fp);
                return $port;
            }
        }

        return false;
    }
}
