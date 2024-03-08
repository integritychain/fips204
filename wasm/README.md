

One-off installation

~~~
$ cargo install wasm-pack
$ sudo npm install npm@latest -g
~~~

To run:

~~~
$ cd wasm    # this directory
$ wasm-pack build
$ cd www
$ npm install
$ export NODE_OPTIONS=--openssl-legacy-provider
$ npm run start
~~~
