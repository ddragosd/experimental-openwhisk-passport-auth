import passport_github from 'passport-github'
import passport_facebook from 'passport-facebook'
import passport_twitter  from 'passport-twitter'
import passport_google from 'passport-google-oauth20'

/**
 * Factory class to create the Passport Strategy corresponding to a given authentication provider.
 */
export default class StrategyFactory {

    /**
     * Returns the instance of the Strategy or an Error object, if the Strategy couldn't be created
     * @param auth_provider the name of the authentication provider
     */
    static getStrategy(auth_provider) {
        let passport_module_name = 'passport-' + auth_provider;
        let strategy_impl = null;

        try {
            strategy_impl = require(passport_module_name).Strategy;
        } catch (err) {
            console.error(err);
            return err;
        }

        return strategy_impl;
    }
}

