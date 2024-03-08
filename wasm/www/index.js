import * as wasm from "wasm";

let wasmForm = document.getElementById("wasmForm");

wasmForm.addEventListener("submit", (e) => {
    e.preventDefault();

    let message = document.getElementById("message");
    let result = "";

    if (message.value) {
        result = wasm.sign(message.value);
        message.value = "";
        document.getElementById("wasm-canvas").innerHTML = result;
    } else {
        alert("Please enter a non-empty message");
    }
});