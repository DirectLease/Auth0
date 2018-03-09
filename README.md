
# Auth0 Authentication for Silverstripe

This a Silverstripe 3 Module for Auth0 that works in combination with the Auth0 Lock.

[Auth0 Lock Docs with examples](https://auth0.com/docs/libraries/lock)


## Config

You can put your auth0 information the 
[config file](_config/auth0.yml)

The follow fields need to be filled:

* URL
* Namespace
* Client_id
* Client_secret
* Audience

You can find these in your client settings in Auth0

**URL**
This is the Domain field in Auth0

**Namespace**
This value is used to parse your user_metadata and (in the upcoming version) app_metadata if you use an auth0 Rule to namespace your user_metadata. If you don't use a Rule you can leave this as an empty string.

We have the following Rule active in Auth0

```javascript
 function (user, context, callback) {
    var namespace = 'https://test.directlease.com/';
    if (context.idToken && user.user_metadata) {
      context.idToken[namespace + 'user_metadata'] = user.user_metadata;
    }
    callback(null, user, context);
  }
```

So our namespace value would be 'https://test.directlease.com'  (ignoring the last backslash from the rule)

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