import passport from 'passport'
import passport_facebook from 'passport-facebook'
import passport_google from 'passport-google'
import passport_github from 'passport-github'


function _authenticate(params) {
    return new Promise((resolve, reject) => {

        let strategy_impl = require('passport-' + params.auth_provider).Strategy;

        let strategy = new strategy_impl({
            clientID: params.client_id,
            clientSecret: params.client_secret,
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


        // a lightweight request object to be used in this serverless context
        let request = {
            query: params // expose query parameters
        };

        // a lightweight response object to be used in this serverless context
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

        let scopes = params.scopes || "";
        scopes = scopes.split(",");

        let res = passport.authenticate(params.auth_provider, {
            scope: scopes , //['user_posts', 'publish_actions'],
            successRedirect: '/success',  // TODO:  TBD should this is read from the parameters ?
            failureRedirect: '/login'     // TODO: TBD should this is read from the parameters ?
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
