# experimental-openwhisk-passport-auth
An Openwhisk action that uses [PassportJS](http://passportjs.org/) for User Authentication Proxy. 


### Quick start

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
        --param callback_url https://<openwhisk_hostname>/api/v1/web/<openwhisk_namespace>/oauth/fb.json
    ```
    
    Configure the default action parameters:
    * `auth_provider` - the name of the authentication provider ( i.e. `facebook`, `github`, etc ).
      The action will try importing `passport-<provider>` lib. You can also add your own authentication provider.
    * `client_id` - consumer key
    * `client_secret` - consumer secret
    * `scopes` - the list of scopes 
    * `callback_url` - this parameter should point to this action

3. To test the action browse to `https://<openwhisk_hostname>/api/v1/web/<openwhisk_namespace>/oauth/<action_name>`

#### Built-in providers

* Facebook
* Google OAuth
* GitHub 


### Adding a custom authentication provider

1. Install the Node module that supports a new provider
2. Import it in the main action [auth.js](src/action/auth.js)
3. Follow the [quick start](#quick-start) steps

### Alternate install
The [quick-start](#quick-start) method it's easy to setup, but the disadvantage is that the code is uploaded 
for each individual action/authentication provider. This makes it more difficult to apply changes. 
OpenWhisk provides a solution for this: [package bindings](https://github.com/openwhisk/openwhisk/blob/master/docs/packages.md#creating-and-using-package-bindings).

With package bindings the action is uploaded and maintained in a single package. Developers may use package binding 
in order to set custom `client_id`, `client_secret`, `scope` for each authentication provider. 
  

 
 