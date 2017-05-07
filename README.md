# experimental-openwhisk-passport-auth
An Openwhisk action that uses [PassportJS](http://passportjs.org/) for User Authentication Proxy.

The scope of this action is to authenticate users, returning an Access Token, a Refresh Token, and the Profile of the user.
The output of this action should be cached, encrypted with Openwhisk's namespace credentials or other means; 
actions belonging to the same package should be able to access this cache, retrieve a valid token, in order to be able to execute actions on behalf of the users.  

<img src="./docs/auth-demo.gif" alt="Demo" style="width:500px;"/>

## Quick start

1. Run `npm install`
2. Create a [webaction](https://github.com/openwhisk/openwhisk/blob/master/docs/webactions.md) for an authentication provider.

    ```bash
    # (optional) place the action in a package
    $ wsk package create oauth

    $ wsk action create oauth/<action_name> ./openwhisk-passport-auth-0.0.1.js  --web true \
        --param auth_provider <authentication_provider> \
        --param client_id <client_id> \
        --param client_secret <client_secret> \
        --param scopes <comma_sepparated_scopes> \
        --param callback_url https://<openwhisk_hostname>/api/v1/web/<openwhisk_namespace>/oauth/<action_name>.json
    ```

    Configure the default action parameters:
    * `auth_provider` - the name of the authentication provider ( i.e. `facebook`, `github`, etc ).
      The action will try importing `passport-<provider>` lib. You can also add your own authentication provider.
    * `auth_provider_name` - optional; defaults to `auth_provider`; it defines an alternate name for the authorization to be used with Passport.  
    * `client_id` - consumer key
    * `client_secret` - consumer secret
    * `scopes` - optional; it defines the list of scopes
    * `callback_url` - this parameter should point to this action

3. To test the action browse to `https://<openwhisk_hostname>/api/v1/web/<openwhisk_namespace>/oauth/<action_name>`

### Using the built-in OAuth providers

The examples bellow assume there is a local OpenWhisk deployment, accessible on `localhost`,
and an `oauth` package already created in OpenWhisk.

```bash
$ wsk package create oauth
```

#### GitHub

Visit https://github.com/settings/developers to create a new application, or to retrieve the `Client ID` and `Client Secret` for an existing application.
 
 > NOTE: When configuring the application in GitHub make sure the `Authorization callback URL` 
 is set to `https://localhost/api/v1/web/guest/oauth/github.json`

Create a new action called `github` inside the `oauth` package.

```bash
$ wsk action create oauth/github ./openwhisk-passport-auth-0.0.1.js --web true \
        --param auth_provider github \ 
        --param client_id --client-id-- \ 
        --param client_secret --client-secret-- \ 
        --param callback_url https://localhost/api/v1/web/guest/oauth/github.json -i
```

Then browse to https://localhost/api/v1/web/guest/oauth/github in order to test the action.
  

#### Facebook
Visit https://developers.facebook.com to create a new application, or to retrieve the `App ID` and the `App secret` for an existing app.

Create a new action called `fb` inside the `oauth` package.

```bash
$ wsk action create oauth/fb ./openwhisk-passport-auth-0.0.1.js --web true \
        --param auth_provider facebook \ 
        --param client_id --app-id-- \ 
        --param client_secret --app-secret-- \ 
        --param callback_url https://localhost/api/v1/web/guest/oauth/fb.json -i
```

Then browse to https://localhost/api/v1/web/guest/oauth/fb in order to test the action.

#### Twitter
Visit https://apps.twitter.com/ to create an application, or to retrieve the `Consumer Key` and `Consumer Secret` for an existing app.

Create a new action called `twitter` inside the `oauth` package.

```bash
$ wsk action create oauth/twitter ./openwhisk-passport-auth-0.0.1.js --web true \ 
        --param auth_provider twitter \ 
        --param client_id --consumer-key-- \ 
        --param client_secret --consumer-secret-- \ 
        --param callback_url https://localhost/api/v1/web/guest/oauth/twitter.json -i
```

Then browse to https://localhost/api/v1/web/guest/oauth/twitter in order to test the action.

#### Google OAuth

Visit https://console.developers.google.com to create a project, or to retrieve the `Client ID ` and `Client Secret` of an existing application.

> NOTE: When configuring credentials in Google select `OAuth Client ID`, `Application Type = Other`.

Create a new action called `google` inside the `oauth` package.

```bash
$ wsk action create oauth/google ./openwhisk-passport-auth-0.0.1.js --web true \ 
        --param auth_provider google-oauth20 --param auth_provider_name google \ 
        --param client_id --client-id-- \ 
        --param client_secret --client-secret-- \ 
        --param scopes https://www.googleapis.com/auth/plus.login \
        --param callback_url https://localhost/api/v1/web/guest/oauth/google.json -i
```

Then browse to https://localhost/api/v1/web/guest/oauth/google in order to test the action.


### Adding a custom authentication provider

1. Install the Node module that supports a new provider
2. Import it in the main action [auth.js](src/action/auth.js)
3. Follow the [quick start](#quick-start) steps

## Using Package Bindings

The [quick-start](#quick-start) method it's easy to setup, but the disadvantage is that the code is uploaded
for each individual action/authentication provider. This makes it more difficult to apply changes.
OpenWhisk provides a solution for this: [package bindings](https://github.com/openwhisk/openwhisk/blob/master/docs/packages.md#creating-and-using-package-bindings).

With package bindings the action is uploaded and maintained in a single package. Developers may use package binding
in order to set custom `client_id`, `client_secret`, `scope` for each authentication provider.

To set this up, start by creating a shared package:
```bash
wsk -i package create oauth --shared yes
```

Then install this action without specifying any default parameters:

```bash
wsk -i action create oauth/user ./openwhisk-passport-auth-0.0.1.js  --web true
```

Then define one or more authentication providers by using package bindings:

```bash
wsk -i package bind oauth/user my-oauth-provider \
--param auth_provider <authentication_provider> \
--param client_id <client_id> \
--param client_secret <client_secret> \
--param scopes <comma_sepparated_scopes> \
--param callback_url https://<openwhisk_hostname>/api/v1/web/<openwhisk_namespace>/oauth/fb.json
```
