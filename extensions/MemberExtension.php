<?php

namespace DirectLease\Auth0\Extensions;

use DirectLease\Auth0\ApiController;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Core\Config\Configurable;
use SilverStripe\ORM\DataExtension;

/**
 * Class Auth0MemberExtension
 *
 * @author  Arno Bor
 * @package auth0
 */
class MemberExtension extends DataExtension
{
    use Configurable;

    private $auth0Id;
    private $auth0_firstname;
    private $middlename;
    private $lastname;
    private $email;


    public function __construct()
    {
        $properties = $this->config()->get('properties');

        if ($properties) {
            foreach ($properties as $key => $value) {
                $this->{$key} = $value;
            }
        }

        $session = $this->getSession();
        $sessionData = $session->getAll();

        if($sessionData) {
            $this->restoreProperties($sessionData);
        }
    }

    public function setProperty($name, $value)
    {
        $this->{$name} = $value;
        $this->updateSession($name, $value);
    }

    public function getProperty($name)
    {
        if(isset($this->$name))
        {
            return $this->{$name};
        }
        else
        {
            return false;
        }
    }

    public function setAuth0Id($id)
    {
        $this->auth0Id = $id;
        $this->updateSession('auth0Id', $id);
    }

    public function getAuth0Id()
    {
        return $this->auth0Id;
    }

    public function setAuth0Firstname($name)
    {
        $this->auth0_firstname = $name;
        $this->updateSession('firstname', $name);
    }

    public function getAuth0Firstname()
    {
        return $this->auth0_firstname;
    }

    public function setAuth0Middlename($name)
    {
        $this->middlename = $name;
        $this->updateSession('middlename', $name);
    }

    public function getAuth0Middlename()
    {
        return $this->middlename;
    }

    public function setAuth0Lastname($name)
    {
        $this->lastname = $name;
        $this->updateSession('lastname', $name);
    }

    public function getAuth0Lastname()
    {
        return $this->lastname;
    }

    public function setAuth0Email($email)
    {
        $this->email = $email;
        $this->updateSession('email', $email);
    }

    public function getAuth0Email()
    {
        return $this->email;
    }

    public function getAuth0FullName()
    {
        if ($middlename = $this->getAuth0Middlename()) {
            $middlename = ' ' . $middlename . ' ';
        } else {
            $middlename = ' ';
        }
        return $this->getAuth0Firstname() . $middlename . $this->getAuth0LastName();
    }

    public function sendAuth0VerificationMail()
    {
        $controller = new ApiController();
        return $controller->sendVerificationMail();
    }

    private function getSession()
    {
        $request = Injector::inst()->get(HTTPRequest::class);
        return $request->getSession();
    }

    private function updateSession($key, $value)
    {
        $session = $this->getSession();
        $session->set('auth0_' . $key, $value);
    }

    private function restoreProperties($data)
    {
        $auth0Fields = array_filter($data, function ($key) {
            return strpos($key, 'auth0_') === 0;
        }, ARRAY_FILTER_USE_KEY);

        foreach ($auth0Fields as $key => $value) {
            $key = preg_replace('/^auth0_/', '', $key);

            switch ($key) {
                case 'auth0Id':
                    $this->setAuth0Id($value);
                    break;
                case 'firstname':
                    $this->setAuth0Firstname($value);
                    break;
                case 'middlename':
                    $this->setAuth0Middlename($value);
                    break;
                case 'lastname':
                    $this->setAuth0Lastname($value);
                    break;
                case 'email':
                    $this->setAuth0Email($value);
                    break;
                default:
                    $this->setProperty($key, $value);
            }
        }
    }

}
