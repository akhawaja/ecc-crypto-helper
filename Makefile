transpile_coffeescripts:
	./node_modules/.bin/coffee --output ./ --compile --map --no-header --watch ./coffeescripts

tc: transpile_coffeescripts

test:
	@NODE_ENV=test ./node_modules/.bin/mocha -b --reporter spec

test-coveralls:
	$(MAKE) test
	@NODE_ENV=test ./node_modules/.bin/istanbul cover \
	./node_modules/mocha/bin/_mocha --report lcovonly -- -R spec && \
		cat ./coverage/lcov.info | ./node_modules/coveralls/bin/coveralls.js || true
