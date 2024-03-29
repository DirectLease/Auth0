

# Auth0 Authentication for Silverstripe
This a Silverstripe 4 Module for Auth0 that works in combination with the Universal Login.
Whether you want to use the 'Classic' or 'New' Universal Login this module works with both.

[Read more about the Auth0 Universal Login](https://auth0.com/docs/universal-login)

## Overview
This module adds an additional login to your silverstripe setup which can be used by your users as well as your admins.
When you redirect an user to /auth/login (a route provided by this module) the Auth0 SDK will prepare a new login and redirect the user to your auth0 tenant login page (The Universal Login).

On this page an user can either login or register with Auth0 for your application. Once the user has been authenticated by Auth0, he will be redirected to your site to /auth/callback (also provided by this module).
The module will check if a user in your site has the same emailaddress as the authenticated Auth0 user and if so perform a login for this user.
If no matching user is found in your site then the module will try to fallback to a default user, more about that below.

You can add a 'redirect_to' parameter to the /auth/login url and once the user has been logged-in he will be redirected to that URL.
If omitted then the user will be redirected to the homepage. 

####Default user
You may not want to store information of your users/customers in your site database for various reasons (GDPR, Potential security risk in case of a hack, etc).  
But you do want to restrict access to (parts) of your application from the public.
For this purpose we have decided to add a default user login.

A default user is a member object with a fixed e-mail address, no password and fixed permissions for this member.
This member object will be used by every user of your site, besides admins.

You can retrieve all the info of the user from auth0 and assign it to the default member.
This information will then be stored in the session instead of being stored in the database.
Once the user leaves the site the session will be destroyed and his information is no longer in your (company's) possession.
 
If your site uses different groups and permissions for users then this use-case is not for you.
Support for multiple default users is needed then, is not on the roadmap.


## Routes
The following routes can be used with this module

* /auth/login - An user will be send to Auth0 for authentication
  * Optional - you can add a url parameter if you want to redirect the user to a specific URL post login. 
    The param is *redirect_to*, the URL would become auth/login?redirect_to=my-profile to redirect to a my-profile page. 
    It can be an internal or external URL.
* /auth/logout - An user will be logged-out of your site and at Auth0
* /auth/updateUserMetadata - You can update the user metadata at Auth0 (does require a M2M Auth0 application)
* /auth/checkAndCreateAuth0UserAccount - If you want to check if someone already has an Auth0 account and if not create one (does require a M2M Auth0 application)
* /auth/sendVerificationMail - The currently logged-in user will receive an e-mail from Auth0 to verify his account at Auth0 (does require a M2M Auth0 application)
* /auth/getIdByEmail - Post an emailaddress to this route and you get back the users auth0 id if user exists else null

## Installation  
composer require directlease/auth0

## Config
You can put your auth0 information in your site config file.
You can find all required config settings here  

[Example site config file](site_config.yml)

The following config settings are **required**:

* **client_id** - the client id of your auth0 application
* **client_secret** - the client secret of your auth0 application
* **domain** - the domain of your auth0 application
* **redirect_uri** - Auth0 needs a fully qualified URL to your site. Default value is /auth/callback which will be turned into https://www.mysite.com/auth/callback
* **cookie_secret** -  A long secret value auth0 uses to encrypt session cookies, refer to Auth0 docs for explanation 
* **scope** - the scope of attributes you want to retrieve from the user who logs in at Auth0. NOTICE: This is now an array instead of a string.
Default is - 'openid' - 'email' - 'profile'
* **persisent_login** - Do you want the use the persistent login of SilverStripe, true or false.

The following config settings are **optional** based on your implementation:

* **m2m_client_id** - the client id of your machine to machine (M2M) auth0 application (you can choose to create a seperate M2M application and connect that with the management API. If do want to use the management API and want to use the web application you created to connect with it, then use the same client_id and client_secret here as your web application)
* **m2m_client_secret** - the client secret of your machine to machine (M2M) auth0 application
* **namespace** - the namespace used in your auth0 rules 
* **default_mailaddress** - the e-mail address of a the 'default' user (see implementation for info)
* **multi_locale** - Boolean if you use Fluent and want to send the locale to auth0 as an extraParams.

## Minimal setup steps for login
We only cover what is needed to get the module to work, Auth0 allows you to configure so much more.

* Setup an application with the 'regular web application' type for your auth0 tenant.
* Set the Allowed Callback URL of your newly created application with the value of your redirect_uri (https://www.mysite.com/auth/callback)


## User Management
You need to configure the Management API for your tenant and give it the correct scopes for the non-interactive-client in Auth0. The Management API is used in the 'updateToAuth0' function in the Auth0ApiController. 

You need to configure the Allowed Logout URLs in your tenant settings to make the logout function work.

## V4 updates

Redirecting post login:
send the user to the login url (/auth/login) and append ?redirect_to= with your desired URL.
It can be a local url then you just pass /home or /welcome or external https://www.github.com

if you want to use the verification email and other functions that require tokens
You must create an Machine to Machine (M2M) Application in your Auth0 Tenant
And enable the Management API on that application with the correct scopes.
