<?php

namespace DirectLease\Auth0;

use SilverStripe\Control\Controller;
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
        'loginFromAuth0',
        'updateToAuth0',
        'resendVerificationMail',
    );


    private $member = null;

    public function __construct()
    {
        parent::__construct();

        $user = Security::getCurrentUser();

        if($user) {
            $this->member = $user;
        }
    }

    /**
     * After login with the Auth0 Lock this function is called with the user info from auth0
     *
     * @param HTTPRequest $request
     *
     * @return bool
     */
    public function loginFromAuth0(HTTPRequest $request)
    {
        $user = json_decode($request->getBody(), true);
        $default_mailaddress = $this->getDefaultMailaddress();
        // the namespace is set in the Auth0 rule for
        // adding app_metadata and user_metadata to the response
        $namespace = $this->config()->get('namespace');

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
            $identityStore->logIn($existingUser);
            $this->member = $existingUser;
        } else {
            $filters['Email'] = $default_mailaddress;

            $member = Member::get()->filterAny($filters)->first();

            if($member) {
                $identityStore->logIn($member);
                $this->member = $member;
            } else {
                throw new \Error("No member was found with the default emailaddress: $default_mailaddress");
            }
        }

        self::updateUserData($user, false);

        return true;
    }

    /**
     * @param $email
     * @param $password
     * @return mixed
     */
    public function checkAuth0UserAccount($email, $password) {
        $email_string = ':"' . $email . '"';
        $query_string = 'email' . urlencode($email_string) . '&search_engine=v3';

        $response = $this->execute_curl("/api/v2/users?q=" . $query_string, "GET");

        $auth0user = json_decode($response);

        if (empty($auth0user)) {
            return self::createAuth0UserAccount($email, $password);
        } else {
            return $auth0user[0]->user_id;
        }
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
        $client_id = $this->config()->get('client_id');

        $id = isset($input['sub']) ? $input['sub'] : null;
        $user_metadata = isset($input['user_metadata']) ? $input['user_metadata'] : null;
        $app_metadata = isset($input['app_metadata']) ? $input['app_metadata'] : null;
        $connection = isset($input['connection']) ? $input['connection'] : null;
        $email = isset($input['email']) ? $input['email'] : null;

        $fields = array(
            'client_id'     => $client_id,
            'user_metadata' => $user_metadata,
            'app_metadata'  => $app_metadata
        );

        if ($connection) {
            $fields["connection"] = ($input['connection'] == "auth0") ? 'Username-Password-Authentication' : $input['connection'];
            $fields["email"] = $email;
            $fields["email_verified"] = true;
        }

        return $this->execute_curl("/api/v2/users/" . $id, "PATCH", $fields);
    }

    public function resendVerificationMail()
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

        return $this->execute_curl("/api/v2/jobs/verification-email", "POST", $fields);
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
        $current_user->setFirstname($firstname);
        $current_user->setMiddlename($middlename);
        $current_user->setLastname($lastname);
        $current_user->setEmail($mail);

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
    private function createAuth0UserAccount($email, $password) {
        $url = $this->config()->get('url');

        $token = self::getAuth0Token();
        $curl = curl_init();

        // The username field only works if it is enabled in auth0 -> connections -> database
        $fields = array(
            'email' => $email,
            'email_verified' => true,
            'connection' => 'Username-Password-Authentication',
            'password' => $password
        );

        $postfields = json_encode($fields);

        curl_setopt_array($curl, array(
            CURLOPT_URL => $url . "/api/v2/users",
            CURLOPT_CUSTOMREQUEST => "POST",
            CURLOPT_POSTFIELDS => $postfields,
            CURLOPT_HTTPHEADER => array(
                "authorization: Bearer " . $token->access_token,
                "content-type: application/json"
            ),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        ));

        $response = curl_exec($curl);

        // Check if any error occurred
        if (!curl_errno($curl)) {
            $info = curl_getinfo($curl);
            if($info['http_code'] == 201) {
                $auth0user = json_decode($response);
            } else if ($info['http_code'] == 409) {
                // User already exist
                $auth0user = true;
            } else {
                $auth0user = false;
            }
        }

        curl_close($curl);

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
        $fields = array(
            'client_id' => $this->config()->get('client_id'),
            'client_secret' => $this->config()->get('client_secret'),
            'audience' => $this->config()->get('audience'),
            'grant_type' => 'client_credentials'
        );

        $postfields = json_encode($fields);

        $curl = curl_init();
        curl_setopt_array($curl, array(
            CURLOPT_URL => $this->config()->get('url') . "/oauth/token",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_CUSTOMREQUEST => "POST",
            CURLOPT_POSTFIELDS => $postfields,
            CURLOPT_HTTPHEADER => array(
                "content-type: application/json"
            ),
        ));

        $token = curl_exec($curl);
        curl_close($curl);

        $token = json_decode($token);

        return $token;
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
        $address = $this->config()->get('default_mailaddress');
        if($address) {
            return $address;
        } else {
            throw new \Error('The default emailaddress missing in your configuration');
        }
    }

    private function execute_curl($url, $type, array $fields = []) {
        $base_url = $this->config()->get('url');
        $token = self::getAuth0Token();

        $postfields = json_encode($fields);

        $curl = curl_init();

        curl_setopt_array($curl, array(
            CURLOPT_URL => $base_url . $url,
            CURLOPT_CUSTOMREQUEST => $type,
            CURLOPT_POSTFIELDS => $postfields,
            CURLOPT_HTTPHEADER => array(
                "authorization: Bearer " . $token->access_token,
                "content-type: application/json"
            ),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
        ));

        $response = curl_exec($curl);

        curl_close($curl);

        return $response;
    }

}
