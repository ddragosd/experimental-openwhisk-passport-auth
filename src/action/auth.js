import passport from 'passport'
import StrategyBuilder from './strategy/builder'

function _authenticate(params) {
    return new Promise((resolve, reject) => {

        //build a strategy for Passport based on input params
        let builder = new StrategyBuilder()
            .withProvider(params.auth_provider)
            .withCredentials(params.client_id, params.client_secret)
            .withCallbackURL(params.callback_url)
            .withVerifyer(function (accessToken, refreshToken, profile, done) {
                console.log("Logged in successfully ... ");
                response.body = {
                    "token": accessToken,
                    "refreshToken": refreshToken,
                    "profile": profile
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
