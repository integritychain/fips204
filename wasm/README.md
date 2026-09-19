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
| `www/` | Webpack + `webpack-dev-server` front end (`package-lock.json` is tracked for reproducible installs) |


## Optional: OS RNG in the browser

This demo does not need OS entropy. If you change the code to use `getrandom` /
`OsRng` on `wasm32-unknown-unknown`, enable getrandom’s JS backend **and** select it
with a cfg (see the [getrandom WebAssembly docs](https://docs.rs/getrandom)):

~~~
# Cargo.toml already has: getrandom = { version = "0.3", features = ["wasm_js"] }
$ RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build
~~~

Or set the same `rustflags` under `[target.wasm32-unknown-unknown]` in
`.cargo/config.toml`.
