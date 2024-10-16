This is a simple WASM demo for the FIPS 204 code.


1. One-off installation

   ~~~
   $ cargo install wasm-pack
   $ <install Node.js if not already installed>
   $ sudo apt install npm
   ~~~

2. To run the demo:

   ~~~
   $ cd wasm    # this directory
   $ wasm-pack build
   $ cd www
   $ npm install  # optionally followed by "npm audit fix"
   $ export NODE_OPTIONS=--openssl-legacy-provider
   $ npm run start
   
   browse http://localhost:8080/
   ~~~

If the final step fails on newer Node.js versions, try preceding
it with: $ export NODE_OPTIONS=--openssl-legacy-provider.
