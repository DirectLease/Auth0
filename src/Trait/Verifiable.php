<?php

namespace DirectLease\Auth0;

use SilverStripe\Security\Security;

trait Verifiable
{

    public function __construct()
    {
        parent::__construct();
        
        $member = Security::getCurrentUser();

        if($member && !$member->auth0Verified) {
            $this->redirect('/verify-member');
        } else if(!$member){
            Security::permissionFailure();
        }
    }
}
