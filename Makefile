test:
	@NODE_ENV=test ./node_modules/.bin/mocha -b --reporter spec --timeout 30000

test-coveralls:
	$(MAKE) test
	@NODE_ENV=test ./node_modules/.bin/istanbul cover \
	./node_modules/mocha/bin/_mocha --report lcovonly -- -R spec && \
		cat ./coverage/lcov.info | ./node_modules/coveralls/bin/coveralls.js || true

.PHONY: test test-coveralls
