
# Auth0 Authentication for Silverstripe

This a Silverstripe 4 Module for Auth0 that works in combination with the Auth0 Lock.

[Auth0 Lock Docs with examples](https://auth0.com/docs/libraries/lock)

## Installation  

composer require directlease/auth0


## Config

You can put your auth0 information the 
[config file](_config/auth0.yml)

The following fields need to be filled:

* URL
* Client_id
* Client_secret
* Audience

You can find these in your client settings in Auth0

**URL**  
This is the Domain field in Auth0

**Client_id**  
The client id of your auth0 client

**Client_secret**  
The client secret of your auth0 client

**Audience**  
The URL you want to use as your Auth0 audience

## Setup

You need to register for an account at Auth0 and setup a tenant.  
Next you need to setup a client for your tenant.

Set the Allowed Callback URLs and Connections for your client 

You need to configure the Management API for your tenant and give it the correct scopes for the non-interactive-client in Auth0. The Management API is used in the 'updateToAuth0' function in the Auth0ApiController. 

You need to configure the Allowed Logout URLs in your tenant settings to make the logout function work.

##

What we have done is make /Security/login the leading URL for all login actions. 
We use the BackURL from SS to redirect the user, once he logged in with the Auth0 Lock, back to the page he wanted to visit. 



## V4 updates

Redirecting post login:
send the user to the login url (/auth/login) and append ?redirect_to= with your desired URL.
It can be a local url then you just pass /home or /welcome or external https://www.github.com

if you want to use the verifcation email and other functions that require tokens
You must create an Machine to Machine (M2M) Application in your Auth0 Tenant
And enable the Management API on that application with the correct scopes.
