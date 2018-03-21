<?php

/**
 * Class Auth0ApiController
 * 
 * @author Arno Bor
 * @package auth0
 */
class Auth0ApiController extends Controller
{

    /** @var array $allowed_actions */
    private static $allowed_actions = array('loginFromAuth0', 'updateToAuth0', 'logoutFromAuth0');

    /** @var array $url_handlers */
    private static $url_handlers = array('loginFromAuth0' => 'loginFromAuth0', 'updateToAuth0' => 'updateToAuth0', 'logoutFromAuth0' => 'logoutFromAuth0');

    /**
     * POST: Login Silverstripe from Auth0
     *
     * @param SS_HTTPRequest $resource
     * @return boolean
     */
    public function loginFromAuth0(SS_HTTPRequest $request)
    {

        try
        {
            $user = $request->postVars();
        } catch (Exception $ex)
        {
            $user = null;
            SS_Log::log($ex, SS_Log::WARN);
            return false;
        }

        // @link https://auth0.com/docs/user-profile
        $id = isset($user['sub']) ? $user['sub'] : null;
        $last_update = isset($user['updated_at']) ? $user['updated_at'] : null;
        $email = isset($user['email']) ? $user['email'] : null;
        $email_verified = isset($user['email_verified']) ? $user['email_verified'] : null;
        $locale = isset($user['locale']) ? $user['locale'] : null;
        $avatar = isset($user['picture_large']) ? $user['picture_large'] : null;
        if (!$avatar)
        {
            $avatar = isset($user['picture']) ? $user['picture'] : null;
        }
        $socialId = isset($user['third_party_id']) ? $user['third_party_id'] : null;

        /* @var $singl Member */
        $singl = singleton('Member');

        $filters = [];
        if ($email)
        {
            $filters['Email'] = $email;
        }
        if ($socialId && $singl->hasField('SocialId'))
        {
            $filters['SocialId'] = $socialId;
        }


        if (empty($filters))
        {
            SS_Log::log("No filters for user " . json_encode($user), SS_Log::DEBUG);
            return false;
        }

        /* @var $member Member */
        $member = Member::get()->filterAny($filters)->first();

        // Email may not be shared and we need it to create a member. Store data for a prefilled register form
        if (!$email && !$member)
        {
            Session::set('RegisterForm.Data', [
                'FromAuth0' => true,
                'SocialId' => $socialId,
                'UserData' => $user,
            ]);
            return false;
        }

        $last_update_stamp = null;

        if ($last_update)
        {
            $stamp_with_microseconds = preg_replace("/[^-:0-9,.]/", " ", $last_update);
            $stamp = substr($stamp_with_microseconds, 0, strpos($stamp_with_microseconds, "."));
            $last_update_stamp = DateTime::createFromFormat('Y-m-d H:i:s', $stamp);
        }


        if ($member)
        {
            if ($member->Auth0LastUpdate != $last_update_stamp->format('Y-m-d H:i:s'))
            {
                $member->Email = $email;
                $member->EmailVerified = $email_verified;
                $member->Auth0Id = $id;
                $member->Auth0LastUpdate = $last_update_stamp->format('Y-m-d H:i:s');
                $member->write();
            }
            $member->logIn();
        } else
        {
            $member = self::storeMember($email, $email_verified, $id, $last_update_stamp, $locale);
            $member->logIn();
        }

        return true;
    }
    
    /**
     *  Create a Member for the Auth0 user
     *
     * @param string $email
     * @param boolean $email_verified
     * @param string $id
     * @param string $email
     * @param DateTime $last_update_stamp
     * @param string $locale
     * @return Object
     */
    public function storeMember($email, $email_verified, $id, $last_update_stamp, $locale)
    {
        $member = Member::create();
        $member->Email = $email;
        $member->EmailVerified = $email_verified;
        $member->Auth0Id = $id;
        $member->Auth0LastUpdate = $last_update_stamp->format('Y-m-d H:i:s');
        $member->Locale = i18n::get_locale_from_lang($locale);
        $member->write();

        // Store image
        if ($member->hasField('AvatarID'))
        {
            $image = self::storeRemoteImage(@file_get_contents($avatar), 'Avatar' . $member->ID, 'Avatars');
            if ($image)
            {
                $member->AvatarID = $image->ID;
                $member->write();
            }
        }

        return $member;
    }
    
    /**
     * Retrieve a Auth0 Token
     *
     * @return Object
     */
    public function getAuth0Token()
    {

        $token = Session::get('auth0Token');
        if ($token)
        {
            return $token;
        } else
        {
            $url = Auth0::config()->url;
            $client_id = Auth0::config()->client_id;
            $client_secret = Auth0::config()->client_secret;
            $audience = Auth0::config()->audience;

            $fields = array(
                'client_id' => $client_id,
                'client_secret' => $client_secret,
                'audience' => $audience,
                'grant_type' => 'client_credentials'
            );

            $postfields = json_encode($fields);
            
            $curl = curl_init();
            curl_setopt_array($curl, array(
                CURLOPT_URL => $url . "/oauth/token",
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
            $err = curl_error($curl);

            curl_close($curl);

            $token = json_decode($token);
            Session::set('auth0Token', $token);

            return $token;
        }
    }
    
    /**
     * POST: Update user metadata on Auth0
     *
     * @param SS_HTTPRequest $resource
     * @return Object
     */
    public function updateToAuth0(SS_HTTPRequest $resource)
    {
        $url = Auth0::config()->url;
        $client_id = Auth0::config()->client_id;

        $user = $resource->postVars();
        $id = isset($user['sub']) ? $user['sub'] : null;
        $user_metadata = isset($user['user_metadata']) ? $user['user_metadata'] : null;
        $app_metadata = isset($user['app_metadata']) ? $user['app_metadata'] : null;
        $connection = isset($user['connection']) ? $user['connection'] : null;
        $email = isset($user['email']) ? $user['email'] : null;

        $token = self::getAuth0Token();
        $curl = curl_init();

        $fields = array(
            'client_id' => $client_id,
            'user_metadata' => json_encode($user_metadata),
            'app_metadata' => json_encode($app_metadata)
        );

        if ($connection)
        {
            $fields["connection"] = $connection;
            $fields["email"] = $email;
            $fields["email_verified"] = true;
        }

        $postfields = json_encode($fields);

        curl_setopt_array($curl, array(
            CURLOPT_URL => $url . "/api/v2/users/" . $id,
            CURLOPT_CUSTOMREQUEST => "PATCH",
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

        $auth0user = curl_exec($curl);
        $err = curl_error($curl);


        curl_close($curl);

        if ($err)
        {
            echo "cURL Error #:" . $err;
        }

        return $auth0user;
    }
    
    /**
     * POST: Logout from Auth0
     *
     * @param SS_HTTPRequest $resource
     * @return boolean
     */
    public function logoutFromAuth0(SS_HTTPRequest $resource)
    {
        $user = $resource->postVars();
        $email = isset($user['email']) ? $user['email'] : null;

        $filters = [];
        if ($email)
        {
            $filters['Email'] = $email;
        }

        $member = Member::get()->filterAny($filters)->first();
        if ($member)
        {
            $member->logOut();
            return true;
        } else
        {
            return false;
        }
    }

    /**
     * Store an image
     *
     * @param string $data
     * @param string $name
     * @param string $folder
     * @return Image
     */
    public static function storeRemoteImage($data, $name, $folder)
    {
        if (!$data)
        {
            return;
        }

        $filter = new FileNameFilter;
        $name = $filter->filter($name);

        $folderName = $folder;
        $folderPath = BASE_PATH . '/assets/' . $folderName;
        $filename = $folderPath . '/' . $name;
        $folderInst = Folder::find_or_make($folderName);
        file_put_contents($filename, $data);
        $folderInst->syncChildren();

        return Image::find($folderName . '/' . $name);
    }

}
