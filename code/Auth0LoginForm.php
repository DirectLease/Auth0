<?php
/**
 * Class Auth0LoginForm
 * 
 * @author Arno Bor
 * @package auth0
 */
class Auth0LoginForm extends LoginForm
{

    protected $authenticator_class = 'Auth0Authenticator';

    function __construct($controller, $name, $fields = null, $actions = null, $checkCurrentUser = true)
    {
        $fields = new FieldList();
        $actions = new FieldList();

        parent::__construct($controller, $name, $fields, $actions);
    }
}

?>
