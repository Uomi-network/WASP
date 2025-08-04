#!/bin/bash
cd agent-template 
cargo build --target wasm32-unknown-unknown --release
cd ..
DIR=${PWD##*/}
DIR=${DIR//-/_}
cp ./target/wasm32-unknown-unknown/release/$DIR.wasm ./host/src/agent_template.wasm
cd host
cargo run
