import chai from 'chai';
import {
    expect
} from 'chai';
import chaiAsPromised from 'chai-as-promised';
import StrategyFactory from '.././../src/action/strategy/factory';

chai.config.includeStack = true;
chai.use(chaiAsPromised);
chai.should();

describe('StrategyFactory', () => {
    describe('with an authentication provider', () => {

        it('like GitHub, should create the correct instance', (done) => {
            let params = {
                auth_provider: "github"
            };

            let result = StrategyFactory.getStrategy(params.auth_provider);
            expect(result.name).to.equal("Strategy");
            done();
        });

        it('which is not imported, should return an error', (done) => {
            let result = StrategyFactory.getStrategy("invalid");
            expect(result).to.be.an.instanceOf(Error);
            done();
        })

    })
});
