<?php

namespace DirectLease\Auth0;

use SilverStripe\Security\Security;

trait Verifiable
{

    public function isMemberVerified()
    {
        $member = Security::getCurrentUser();

        if($member && !$member->auth0Verified)
        {
            // TODO: Make config setting for URL if empty return a false and else true
            return $this->redirect('verificatie/');
        }
    }

}
