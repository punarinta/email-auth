<?php

namespace EmailAuth;

class Dns
{
    /**
     * Finds an MX record with a highest priority
     *
     * @param $domain
     * @return null
     */
    static public function getTopMx($domain)
    {
        $priority = -1;
        $record = null;

        foreach (dns_get_record($domain, DNS_MX) as $row)
        {
            if (-1 == $priority || $row['pri'] < $priority)
            {
                $priority = $record['pri'];
                $record = $row;
            }
        }

        return $record ? $record['target'] : null;
    }
}
