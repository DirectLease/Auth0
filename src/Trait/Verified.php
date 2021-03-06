<?php

namespace DirectLease\Auth0;

use SilverStripe\Core\Config\Config;
use SilverStripe\Security\Security;

trait Verified
{
    /**
     * @return bool
     */
    public function isMemberVerified()
    {
        $member = Security::getCurrentUser();

        if($member && !$member->auth0Verified)
        {
            $url = Config::inst()->get(Verified::class, 'verification_uri');

            if($url)
            {
                return $this->redirect($url);
            }

            return false;
        }

        return true;
    }

}
