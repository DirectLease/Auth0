<?php

namespace DirectLease\Auth0\Extensions;

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
    private $firstname;
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
        return $this->{$name};
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

    public function setFirstname($name)
    {
        $this->firstname = $name;
        $this->updateSession('firstname', $name);
    }

    public function getFirstname()
    {
        return $this->firstname;
    }

    public function setMiddlename($name)
    {
        $this->middlename = $name;
        $this->updateSession('middlename', $name);
    }

    public function getMiddlename()
    {
        return $this->middlename;
    }

    public function setLastname($name)
    {
        $this->lastname = $name;
        $this->updateSession('lastname', $name);
    }

    public function getLastname()
    {
        return $this->lastname;
    }

    public function setEmail($email)
    {
        $this->email = $email;
        $this->updateSession('email', $email);
    }

    public function getEmail()
    {
        return $this->email;
    }

    public function getFullName()
    {
        if ($middlename = $this->getMiddlename()) {
            $middlename = ' ' . $middlename . ' ';
        } else {
            $middlename = ' ';
        }
        return $this->getFirstname() . $middlename . $this->getLastName();
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
                    $this->setFirstname($value);
                    break;
                case 'middlename':
                    $this->setMiddlename($value);
                    break;
                case 'lastname':
                    $this->setLastname($value);
                    break;
                case 'email':
                    $this->setEmail($value);
                    break;
                default:
                    $this->setProperty($key, $value);
            }
        }
    }

}
