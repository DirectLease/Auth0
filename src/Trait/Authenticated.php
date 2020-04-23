<?php

namespace DirectLease\Auth0;

use SilverStripe\Security\Security;

trait Authenticated
{
    /**
     * @return bool
     */
    public function isMemberAuthenticated()
    {
        $member = Security::getCurrentUser();

        if(!$member) {
            return $this->redirect('auth/login/');
        }

        return true;

    }

}
