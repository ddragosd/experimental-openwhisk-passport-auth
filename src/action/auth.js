import passport from 'passport'
import StrategyBuilder from './strategy/builder'
import cookie from 'cookie'

function _authenticate(params) {
    return new Promise((resolve, reject) => {

        //build a strategy for Passport based on input params
        let builder = new StrategyBuilder()
            .withProvider(params.auth_provider)
            .withCredentials(params.client_id, params.client_secret)
            .withCallbackURL(params.callback_url)
            .withVerifyer(function (accessToken, refreshToken, profile, done) {
                console.log("Logged in successfully ... ");
                let ctx = _updateContext(params, profile);
                ctx.success_redirect = ctx.success_redirect || params.redirect_url;
                response.body = {
                    "token": accessToken,
                    "refreshToken": refreshToken,
                    "profile": profile,
                    "context": ctx
                };

                resolve(get_action_response(response));
            });

        let strategy = builder.buildStrategy();

        if (strategy === null) {
            reject({
                    "message": "Could not load " + params.auth_provider,
                    "error": builder.getError().toString()
                }
            );
        }

        // create a lightweight request object to be used in the serverless context
        let request = {
            query: params,     // expose query parameters
            session: strategy._requestTokenStore || strategy._stateStore // inherit the session from Passport
        };

        // create a lightweight response object to be used in the serverless context
        let response = {
            headers: {},
            setHeader: function (name, val) {
                response.headers[name] = val;
            },
            end: function () {
                console.log("response end()");
                resolve(get_action_response(response));
            }
        };

        let get_action_response = function (resp) {
            if (resp.body instanceof Error) {
                console.error(resp.body);
                resp.body = resp.body.toString();
            }
            // save the success_redirect in a cookie to
            //   set it in the context once the user logs in
            if (resp.statusCode == 302) {
              let cookie_header = resp.headers['Set-Cookie'];
              if ((cookie_header === null || typeof(cookie_header) === "undefined") &&
                 (params.success_redirect !== null && typeof(params.success_redirect) !== "undefined")) {
                let ctx = _getContext(params);
                ctx.success_redirect = params.success_redirect;
                resp.headers["Set-Cookie"] = '__Secure-auth_context=' + JSON.stringify(ctx) + '; Secure; HttpOnly; Max-Age=600; Path=/api/v1/web/' + process.env['__OW_NAMESPACE']
              }
            }

            return {
                headers: resp.headers,
                statusCode: resp.statusCode,
                body: resp.body || ''
            }

        };

        let next = function (opts) {
            console.log("next()");
            response.body = opts;
            resolve(get_action_response(response));
        };

        passport.use(strategy);

        let scopes = params.scopes || null;
        if (scopes !== null) {
            scopes = scopes.split(",");
        }

        let res = passport.authenticate(params.auth_provider_name || params.auth_provider, {
            scope: scopes,
            successRedirect: '/success',  // TODO: TBD should this be read from parameters ?
            failureRedirect: '/login'     // TODO: TBD should this be read from parameters ?
        });

        res(request, response, next);

    });
}

function _getContext(params) {
  const CONTEXT_COOKIE_NAME = "__Secure-auth_context";
  //console.log("Cookies:" + params.__ow_headers['cookie']);
  let cookies = cookie.parse(params.__ow_headers['cookie'] || '');
  //console.log("Cookies parsed:" + JSON.stringify(cookies));
  return cookies[CONTEXT_COOKIE_NAME] ? JSON.parse(cookies[CONTEXT_COOKIE_NAME]) : {};
}

/**
* Returns a context object for this action.
* If this action is used to link multiple social IDs together
*  it reads the linked identities from a Cookie named "auth_context".
*  For Example the cookie header might be
*      Cookie: "auth_context={"identities":[{"provider":"adobe","user_id":"123"}
*  In this case the context.identities object is populated with the value from the cookie
* This context object should be used by another action in order to persist
*   the information about the linked accounts
*
* @param params Action input parameters
* @param profile User Profile
*/
function _updateContext(params, profile) {
  let ctx = _getContext(params);
  //console.log("ctx.identities=" + JSON.stringify(ctx.identities));
  // NOTE: there's no check for duplicated providers, ne design.
  //       2 accounts from the same provider can be linked together as well.
  // avoid duplicated identities
  let identity_exists = false;
  let provider = (params.auth_provider_name || params.auth_provider)
  ctx.identities = ctx.identities || [];
  for (var i=0; i<ctx.identities.length; i++ ){
    let ident = ctx.identities[i];
    if (ident !== null && typeof(ident) !== "undefined" &&
        ident.provider == provider && ident.user_id == profile.id) {
      identity_exists = true;
      return ctx;
    }
  }
  ctx.identities.push({
    "provider": (params.auth_provider_name || params.auth_provider),
    "user_id": profile.id
  });
  return ctx;
}


/**
 * The entry point for the action.
 * @param params Input object
 * @returns {Promise}
 */
function main(params) {
    console.log(params);
    return _authenticate(params);
}

export default main;
