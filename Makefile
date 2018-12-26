transpile_coffeescripts:
	./node_modules/.bin/coffee --output ./ --compile --map --no-header --watch ./coffeescripts

tc: transpile_coffeescripts
