import passport from 'passport'
import passport_github from 'passport-github'
import passport_facebook from 'passport-facebook'
import passport_twitter  from 'passport-twitter'
import passport_google from 'passport-google'

function _authenticate(params) {
    return new Promise((resolve, reject) => {

        let passport_module_name = 'passport-' + params.auth_provider;

        let strategy_impl = null;

        try {
            strategy_impl = require(passport_module_name).Strategy;
        } catch (err) {
            console.log(err);
            reject({
                    "message": "Could not load " + passport_module_name,
                    "error": err.toString()
                }
            );
        }


        let strategy = new strategy_impl({
            clientID: params.client_id,
            consumerKey: params.client_id,
            clientSecret: params.client_secret,
            consumerSecret: params.client_secret,
            callbackURL: params.callback_url
        }, function (accessToken, refreshToken, profile, done) {
            console.log("Logged in successfully ... ");
            response.body = {
                "token": accessToken,
                "refreshToken": refreshToken,
                "profile": profile
            };

            resolve(get_action_response(response));
        });


        // a lightweight request object to be used in the serverless context
        let request = {
            query: params,     // expose query parameters
            session: strategy._requestTokenStore || strategy._stateStore // inherit the session from Passport
        };

        if (strategy._requestTokenStore) { // OAuth 1 requires a session
            strategy._requestTokenStore.get = function(req, token, cb) {
                // NOTE: The oauth_verifier parameter will be supplied in the query portion
                //       of the redirect URL, if the server supports OAuth 1.0a.
                var oauth_verifier = req.query.oauth_verifier || null;
                return cb(null, oauth_verifier);
            }
            strategy._requestTokenStore.destroy = function(req, token, cb) {
                // simply invoke the callback directly
                cb();
            }
        }

        // a lightweight response object to be used in the serverless context
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
        if ( scopes !== null ) {
            scopes = scopes.split(",");
        }

        let res = passport.authenticate(params.auth_provider, {
            scope: scopes,
            successRedirect: '/success',  // TODO: TBD should this be read from parameters ?
            failureRedirect: '/login'     // TODO: TBD should this be read from parameters ?
        });

        res(request, response, next);

    });
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
