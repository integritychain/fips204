# WASM demo for FIPS 204

Browser demo that builds this crate to WebAssembly (`wasm-pack`) and serves a small
Webpack app under [`www/`](www/).

The demo uses a **fixed ChaCha8 seed** so results can be compared with native tests. It
does not call the OS RNG at runtime.


## Prerequisites

1. Rust toolchain with the `wasm32-unknown-unknown` target  
   (`rustup target add wasm32-unknown-unknown`)
2. [`wasm-pack`](https://rustwasm.github.io/wasm-pack/)  
   (`cargo install wasm-pack`)
3. **Node.js** with npm (LTS is fine). Install from [nodejs.org](https://nodejs.org/)
   or your OS package manager / version manager (`nvm`, `fnm`, etc.). You do **not**
   need a separate `apt install npm` if your Node install already includes npm.


## Run the demo

~~~
$ cd wasm    # this directory
$ wasm-pack build
$ cd www
$ npm install
$ npm run start
~~~

Then open http://localhost:8080/ .


## Layout

| Path | Role |
|---|---|
| `src/` | Rust crate (`fips204-wasm`) with a `sign` export |
| `pkg/` | Produced by `wasm-pack build` (gitignored); consumed by `www/` as `file:../pkg` |
| `www/` | Webpack + `webpack-dev-server` front end |


## Optional: OS RNG in the browser

This demo does not need OS entropy. If you change the code to use `getrandom` on
`wasm32-unknown-unknown`, this crate already depends on `getrandom` 0.2 with the
`js` feature, which is the backend for that version.
