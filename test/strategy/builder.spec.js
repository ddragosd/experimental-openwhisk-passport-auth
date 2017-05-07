import chai from 'chai';
import {
    expect
} from 'chai';
import chaiAsPromised from 'chai-as-promised';
import StrategyBuilder from '.././../src/action/strategy/builder';

chai.config.includeStack = true;
chai.use(chaiAsPromised);
chai.should();

describe('StrategyBuilder', () => {
    describe('build Strategy', () => {

        it('should use the correct values', (done) => {
            let params = {
                auth_provider: "github",
                client_id: "test_client_id",
                client_secret: "test_client_secret",
                scopes: "user_posts,publish_actions",
                callback_url: "http://www.example.com/auth/facebook/callback"
            };

            let builder = new StrategyBuilder()
                .withProvider(params.auth_provider)
                .withCredentials(params.client_id, params.client_secret)
                .withCallbackURL(params.callback_url)
                .withVerifyer(function (accessToken, refreshToken, profile, done_cb) {
                    done();
                });

            let strategy = builder.buildStrategy();

            expect(builder.auth_provider).to.equal(params.auth_provider);
            expect(builder.client_id).to.equal(params.client_id);
            expect(builder.client_secret).to.equal(params.client_secret);
            expect(builder.callback_url).to.equal(params.callback_url);

            expect(strategy.name).to.equal("github");

            done();
        });

        it('should fail gracefully', (done) => {
            let params = {
                auth_provider: "invalid",
                client_id: "test_client_id",
                client_secret: "test_client_secret",
                scopes: "user_posts,publish_actions",
                callback_url: "http://www.example.com/auth/facebook/callback"
            };

            let builder = new StrategyBuilder()
                .withProvider(params.auth_provider)
                .withCredentials(params.client_id, params.client_secret)
                .withCallbackURL(params.callback_url)
                .withVerifyer(function (accessToken, refreshToken, profile, done_cb) {
                    done();
                });

            let strategy = builder.buildStrategy();

            expect(builder.auth_provider).to.equal(params.auth_provider);
            expect(builder.client_id).to.equal(params.client_id);
            expect(builder.client_secret).to.equal(params.client_secret);
            expect(builder.callback_url).to.equal(params.callback_url);

            expect(strategy).to.be.null;

            expect(builder.getError().toString()).to.equal("Error: Cannot find module \'passport-invalid\'");

            done();
        });

    })
});
