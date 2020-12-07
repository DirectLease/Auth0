<?php

namespace DirectLease\Auth0;

use Auth0\SDK\API\Authentication;
use Auth0\SDK\Auth0;
use GuzzleHttp;
use GuzzleHttp\Exception\ClientException;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Security\IdentityStore;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;


/**
 * Class Auth0ApiController
 *
 * @author  Arno Bor
 * @package auth0
 */
class ApiController extends Controller
{

    /** @var array $allowed_actions */
    private static $allowed_actions = array(
        'login',
        'logout',
        'callback',
        'updateProfile',
        'updateUserMetadata',
        'sendVerificationMail',
        'checkAndCreateAuth0UserAccount',
    );


    private $member;
    private $auth0;
    private $domain;
    private $client_id;
    private $client_secret;
    private $redirect_uri;
    private $scope;
    private $default_email;
    private $namespace;
    private $url;
    private $persistent_login;

    public function __construct()
    {
        parent::__construct();

        $user = Security::getCurrentUser();

        if($user) {
            $this->member = $user;
        }

        $this->domain = $this->config()->get('domain');
        $this->client_id = $this->config()->get('client_id');
        $this->client_secret = $this->config()->get('client_secret');
        $this->redirect_uri = Director::protocolAndHost() . $this->config()->get('redirect_uri');
        $this->scope = $this->config()->get('scope');
        $this->default_email = $this->config()->get('default_mailaddress');
        $this->namespace = $this->config()->get('namespace');
        $this->url = 'https://' . $this->domain;
        $this->persistent_login = $this->config()->get('persisent_login');

    }

    public function signup() {
        $this->login(true);
    }

    public function login($isSignup=false)
    {
        // handle redirect back correctly
        $redirect_to = $this->request->getVar('redirect_to');

        if($this->request->getVar('BackURL'))
        {
            $redirect_to = $this->request->getVar('BackURL');
        }

        $extraAuth0Params = array();
        $action="login";

        // Show register tab instead of login tab
        if ($isSignup === true) {
            $action='signup';
            // set config param for the lock so it opens up in signup tab
            $extraAuth0Params = array('auth_action'=>'signup');
        }

        // Due to browser logging in and out could lead to invalid states
        // So we are now making sure every login request is unique
        if (!$this->request->getVar('uid'))
        {
            return $this->redirect('/auth/'.$action.'?redirect_to=' . $redirect_to . '&uid=' . uniqid());
        }

        $this->setup($redirect_to);

        $this->auth0->login('','',$extraAuth0Params);
    }

    public function logout()
    {
        $identityStore = Injector::inst()->get(IdentityStore::class);
        $identityStore->logOut($this->request);

        $auth_api = new Authentication($this->domain, $this->client_id);

        $this->setup();

        $this->auth0->logout();

        $this->redirect($auth_api->get_logout_link(Director::absoluteBaseURL(), $this->client_id));
    }

    /**
     * Get the authenticated user and login in SS
     *
     * @return bool
     * @throws \Auth0\SDK\Exception\ApiException
     * @throws \Auth0\SDK\Exception\CoreException
     */
    public function callback()
    {
        $this->setup();
        $redirect_to = $this->request->getVar('redirect_to');
        $user = $this->auth0->getUser();
        // the namespace is set in the Auth0 rule for
        // adding app_metadata and user_metadata to the response
        $namespace = $this->namespace;

        if (!$user) {
            return false;
        }
        if (isset($user[$namespace . "user_metadata"])) {
            $user["user_metadata"] = $user[$namespace . "user_metadata"];
            unset($user[$namespace . "user_metadata"]);
        }

        if (isset($user[$namespace . "app_metadata"])) {
            $user["app_metadata"] = $user[$namespace . "app_metadata"];
            unset($user[$namespace . "app_metadata"]);
        }

        $filters['Email'] = $user["email"];
        $identityStore = Injector::inst()->get(IdentityStore::class);
        $existingUser = Member::get()->filterAny($filters)->first();

        if ($existingUser) {
            $identityStore->logIn($existingUser, $this->persistent_login);
            $this->member = $existingUser;
        } else {
            $default_mailaddress = $this->getDefaultMailaddress();
            $filters['Email'] = $default_mailaddress;

            $member = Member::get()->filterAny($filters)->first();

            if($member) {
                $identityStore->logIn($member, $this->persistent_login);
                $this->member = $member;
            } else {
                throw new \Error("No member was found with the default emailaddress: $default_mailaddress");
            }
        }

        self::updateUserData($user, false);

        $this->redirect($redirect_to);
    }

    /**
     * @param $email
     * @param $password
     * @return mixed
     */
    public function checkAndCreateAuth0UserAccount()
    {
        $email = $this->request->postVar('email');
        $password = $this->request->postVar('password');
        $email_string = ':"' . $email . '"';
        $query_string = 'email' . urlencode($email_string) . '&search_engine=v3';

        $response = $this->call_auth0("/api/v2/users?q=" . $query_string, "GET");

        if (empty($response)) {
            return self::createAuth0UserAccount($email, $password);
        } else {
            return $response[0]->user_id;
        }
    }


    public function updateProfile($input)
    {
        $current_user = $this->member;

        $user['sub'] = $current_user->getAuth0Id();
        $user['email'] = $current_user->getAuth0Email();
        $user['email_verified'] = $current_user->getAuth0Verified();
        $user['user_metadata'] = $input->postVars();

        self::updateUserData($user, true);

        $request = Injector::inst()->get(HTTPRequest::class);
        $session = $request->getSession();

        $session->set('ActionStatus', 'success');
        $session->set('ActionMessage', _t(__CLASS__.'.ProfileUpdated', 'Your profile has been updated'));

        $this->redirectBack();
    }

    /**
     * POST: Update user metadata on Auth0
     *
     * @param mixed $input
     *
     * @return bool|Object|string
     */
    public function updateUserMetadata($input)
    {
        $id = isset($input['sub']) ? $input['sub'] : null;
        $user_metadata = isset($input['user_metadata']) ? $input['user_metadata'] : null;
        $app_metadata = isset($input['app_metadata']) ? $input['app_metadata'] : null;
        $connection = isset($input['connection']) ? $input['connection'] : null;
        $email = isset($input['email']) ? $input['email'] : null;

        $fields = array(
            'client_id'     => $this->client_id,
            'user_metadata' => $user_metadata,
            'app_metadata'  => $app_metadata
        );

        if ($connection) {
            $fields["connection"] = ($input['connection'] == "auth0") ? 'Username-Password-Authentication' : $input['connection'];
            $fields["email"] = $email;
            $fields["email_verified"] = true;
        }

        return $this->call_auth0("/api/v2/users/" . $id, "PATCH", $fields);
    }

    public function sendVerificationMail()
    {
        $member = $this->member;

        if (is_null($member)) {
            throw new \Error('You need a logged in member to send a validation email to.');
        }

        $id = $member->Auth0Id;

        // The username field only works if it is enabled in auth0 -> connections -> database
        $fields = array(
            'user_id' => $id,
        );

        $result = $this->call_auth0("/api/v2/jobs/verification-email", "POST", $fields);

        $request = Injector::inst()->get(HTTPRequest::class);
        $session = $request->getSession();

        if($result) {
            $session->set('ActionStatus', 'success');
            $session->set('ActionMessage', _t(__CLASS__.'.VerificationSend', 'The email has been send, please check your mail.'));
        } else {
            $session->set('ActionStatus', 'failed');
            $session->set('ActionMessage', _t(__CLASS__.'.VerificationSendFailed', 'Something went wrong please try again later.'));
        }

        $this->redirectBack();

    }

    /**
     * Update the userdata in SS
     *
     * @param $user
     *
     * @return Member|null
     * @throws Exception
     */
    private function updateUserData($user, $on_auth0 = false)
    {
        // include the fields in the documentation about the recommended usage
        $verified = isset($user['email_verified']) ? $user['email_verified'] : null;
        $id = isset($user['sub']) ? $user['sub'] : null;
        $mail = isset($user['email']) ? $user['email'] : null;
        $app_metadata = isset($user['app_metadata']) ? $user['app_metadata'] : null;
        $user_metadata = isset($user['user_metadata']) ? $user['user_metadata'] : null;
        $gender = isset($user_metadata["gender"]) ? $user_metadata["gender"] : null;
        $firstname = isset($user_metadata['firstname']) ? $user_metadata['firstname'] : null;
        $middlename = isset($user_metadata["insertion"]) ? $user_metadata["insertion"] : null;
        $lastname = isset($user_metadata['lastname']) ? $user_metadata['lastname'] : null;

        // Overwrites for Google
        if (isset($user['given_name'])) {
            $firstname = $user['given_name'];
        }
        if (isset($user['family_name'])) {
            $lastname = $user['family_name'];
        }

        // TODO: make a setting if you use the firstname and lastname from auth0
        // or put it in user meta_data like DL
        $current_user = $this->member;

        if(is_null($current_user)) {
            throw new \Error('You need a logged in member to update his data');
        }

        $current_user->setAuth0Id($id);
        $current_user->setAuth0Firstname($firstname);
        $current_user->setAuth0Middlename($middlename);
        $current_user->setAuth0Lastname($lastname);
        $current_user->setAuth0Email($mail);
        $current_user->setAuth0Verified($verified);

        if ($user_metadata) {
            self::parseMetadata($user_metadata);
        }

        if ($app_metadata) {
            self::parseMetadata($app_metadata);
        }

        if($on_auth0){
            self::updateUserMetadata($user);
        }

        return $current_user;
    }

    /**
     * Create an user account for the member on Auth0
     *
     * @param $email
     * @param $password
     * @return mixed
     */
    private function createAuth0UserAccount($email, $password)
    {
        $token = self::getAuth0Token();

        $client = new GuzzleHttp\Client();

        $headers = [
            'Authorization' => 'Bearer ' . $token->access_token,
            'Accept'        => 'application/json',
        ];

        // The username field only works if it is enabled in auth0 -> connections -> database
        $fields = array(
            'email' => $email,
            'email_verified' => true,
            'connection' => 'Username-Password-Authentication',
            'password' => $password
        );

        $auth0user = null;

        try {
            $result = $client->request('POST', $this->url . "/api/v2/users", [
                'headers'       => $headers,
                'json'          => $fields
            ]);

            $auth0user = $result->getBody()->getContents();
        } catch (ClientException $e) {
            if ($e->getResponse()->getStatusCode() == 409) {
                // User already exist
                $auth0user = true;
            } else if ($e->getResponse()->getStatusCode() == 400) {
                // Mostlikely password is too weak
                return $e->getResponse()->getBody()->getContents();
            } else {
                $auth0user = false;
            }
        }

        if($auth0user && is_object($auth0user)) {
            return $auth0user->user_id;
        } else {
            return $auth0user;
        }
    }


    /**
     * Retrieve a Auth0 Token
     *
     * @return Object
     */
    private function getAuth0Token()
    {
        // TODO: sanity check for m2m config settings
        $fields = array(
            'client_id' => $this->config()->get('m2m_client_id'),
            'client_secret' => $this->config()->get('m2m_client_secret'),
            'audience' => $this->url . '/api/v2/',
            'grant_type' => 'client_credentials'
        );

        $client = new GuzzleHttp\Client();

        $result = $client->request('POST', $this->url . "/oauth/token", [
            'json' => $fields
        ]);

        return json_decode($result->getBody()->getContents());
    }

    /**
     * @param $arr
     */
    private function parseMetadata($arr)
    {
        $user = $this->member;

        if(is_null($user)) {
            throw new \Error('You need a logged in member to set properties');
        }

        if (is_array($arr)) {
            foreach ($arr as $k => $v) {
                $user->setProperty($k, $v);
            }
        }
    }

    /**
     * @return mixed
     */
    private function getDefaultMailaddress()
    {
        $address = $this->default_email;
        if($address) {
            return $address;
        } else {
            throw new \Error('The default emailaddress missing in your configuration');
        }
    }

    private function call_auth0($uri, $type, array $fields = [])
    {
        $token = self::getAuth0Token();

        $client = new GuzzleHttp\Client();

        $headers = [
            'Authorization' => 'Bearer ' . $token->access_token,
            'Accept'        => 'application/json',
        ];

        $result = $client->request($type, $this->url . $uri, [
            'headers'       => $headers,
            'json'          => $fields
        ]);

        return json_decode($result->getBody()->getContents());
    }

    private function setup($url = null)
    {
        $redirect = $this->redirect_uri .= '?redirect_to=' . $url;

        try {
            $this->auth0 = new Auth0([
                'domain' => $this->domain,
                'client_id' => $this->client_id,
                'client_secret' => $this->client_secret,
                'redirect_uri' => $redirect,
                'scope' => $this->scope,
            ]);
        }
        catch (\Auth0\SDK\Exception\CoreException $e) {
            throw new \Error('Auth0 Core Exception' . $e);
        }
    }

}
