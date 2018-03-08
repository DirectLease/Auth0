<?php
/**
 * Class Auth0Authenticator
  * 
 * @author Arno Bor
 * @package auth0
 */
class Auth0Authenticator extends Authenticator
{

    public static function get_login_form(Controller $controller)
    {
        return Object::create("Auth0LoginForm", $controller, "LoginForm");
    }

    public static function get_name()
    {
        return "Auth0 Authenticator";
    }

}

?>