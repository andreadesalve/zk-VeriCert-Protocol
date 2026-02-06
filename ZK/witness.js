
#!/usr/bin/env node

/****************************************************
 *  CLI: generate witness
 ****************************************************/

const { readFileSync, writeFileSync } = require("fs");

// ---------------- CLI ----------------
if (require.main === module) {
    if (process.argv.length !== 5) {
        console.log("Usage: node witness.js <file.wasm> <input.json> <output.wtns>");
        process.exit(1);
    }

    const wasmFile = process.argv[2];
    const inputFile = process.argv[3];
    const outputFile = process.argv[4];

    const input = JSON.parse(readFileSync(inputFile, "utf8"));
    const buffer = readFileSync(wasmFile);

    builder(buffer).then(async wc => {
        const buff = await wc.calculateWTNSBin(input, 0);
        writeFileSync(outputFile, buff);
        console.log("Witness written to:", outputFile);
    }).catch(err => {
        console.error("Error:", err);
        process.exit(1);
    });
}


/****************************************************
 *  BUILDER + WITNESS CALCULATOR
 ****************************************************/

async function builder(code, options = {}) {
    let wasmModule;

    try {
        wasmModule = await WebAssembly.compile(code);
    } catch (err) {
        console.log(err);
        console.log("\nTry to run circom --c to generate C++ code instead.\n");
        throw err;
    }

    let errStr = "";
    let msgStr = "";

    const instance = await WebAssembly.instantiate(wasmModule, {
        runtime: {
            exceptionHandler(code) {
                const msgs = {
                    1: "Signal not found.\n",
                    2: "Too many signals set.\n",
                    3: "Signal already set.\n",
                    4: "Assert Failed.\n",
                    5: "Not enough memory.\n",
                    6: "Input signal array access exceeds the size.\n"
                };
                throw new Error((msgs[code] || "Unknown error.\n") + errStr);
            },
            printErrorMessage() {
                errStr += getMessage() + "\n";
            },
            writeBufferMessage() {
                const msg = getMessage();
                if (msg === "\n") {
                    console.log(msgStr);
                    msgStr = "";
                } else {
                    if (msgStr !== "") msgStr += " ";
                    msgStr += msg;
                }
            },
            showSharedRWMemory() {
                const size = instance.exports.getFieldNumLen32();
                const arr = new Uint32Array(size);
                for (let j = 0; j < size; j++) {
                    arr[size - 1 - j] = instance.exports.readSharedRWMemory(j);
                }
                if (msgStr !== "") msgStr += " ";
                msgStr += fromArray32(arr).toString();
            }
        }
    });

    const wc = new WitnessCalculator(instance, options);

    function getMessage() {
        let msg = "";
        let c = instance.exports.getMessageChar();
        while (c !== 0) {
            msg += String.fromCharCode(c);
            c = instance.exports.getMessageChar();
        }
        return msg;
    }

    return wc;
}


/****************************************************
 *  WITNESS CALCULATOR CLASS
 ****************************************************/

class WitnessCalculator {
    constructor(instance, options) {
        this.instance = instance;

        this.version = instance.exports.getVersion();
        this.n32 = instance.exports.getFieldNumLen32();

        instance.exports.getRawPrime();
        const arr = new Uint32Array(this.n32);
        for (let i = 0; i < this.n32; i++) {
            arr[this.n32 - 1 - i] = instance.exports.readSharedRWMemory(i);
        }
        this.prime = fromArray32(arr);

        this.witnessSize = instance.exports.getWitnessSize();
        this.sanityCheck = !!options;
    }

    async _doCalculateWitness(input_orig, sanityCheck) {
        this.instance.exports.init((this.sanityCheck || sanityCheck) ? 1 : 0);

        const flat = {};
        qualify_input("", input_orig, flat);

        let inputCount = 0;

        for (const k of Object.keys(flat)) {
            const h = fnvHash(k);
            const hMSB = parseInt(h.slice(0, 8), 16) >>> 0;
            const hLSB = parseInt(h.slice(8), 16) >>> 0;

            const values = flatArray(flat[k]);
            const size = this.instance.exports.getInputSignalSize(hMSB, hLSB);

            if (size < 0) throw new Error(`Signal ${k} not found`);
            if (values.length !== size)
                throw new Error(`Wrong number of values for signal ${k}`);

            for (let i = 0; i < values.length; i++) {
                const limbs = toArray32(normalize(values[i], this.prime), this.n32);
                for (let j = 0; j < this.n32; j++) {
                    this.instance.exports.writeSharedRWMemory(j, limbs[this.n32 - 1 - j]);
                }
                this.instance.exports.setInputSignal(hMSB, hLSB, i);
                inputCount++;
            }
        }

        if (inputCount < this.instance.exports.getInputSize()) {
            throw new Error("Not all inputs were supplied");
        }
    }

    async calculateWTNSBin(input, sanityCheck) {
        const total = this.witnessSize * this.n32 + this.n32 + 11;
        const buff32 = new Uint32Array(total);
        const buff = new Uint8Array(buff32.buffer);

        await this._doCalculateWitness(input, sanityCheck);

        // "wtns"
        buff[0] = "w".charCodeAt(0);
        buff[1] = "t".charCodeAt(0);
        buff[2] = "n".charCodeAt(0);
        buff[3] = "s".charCodeAt(0);

        buff32[1] = 2; // version
        buff32[2] = 2; // sections

        buff32[3] = 1; // id section 1

        const n8 = this.n32 * 4;
        const len1 = 8 + n8;
        const hex1 = len1.toString(16).padStart(16, "0");
        buff32[4] = parseInt(hex1.slice(0, 8), 16);
        buff32[5] = parseInt(hex1.slice(8), 16);

        buff32[6] = n8;

        this.instance.exports.getRawPrime();
        let pos = 7;

        for (let j = 0; j < this.n32; j++) {
            buff32[pos + j] = this.instance.exports.readSharedRWMemory(j);
        }
        pos += this.n32;

        buff32[pos] = this.witnessSize;
        pos++;

        buff32[pos] = 2; // section 2 id
        pos++;

        const len2 = n8 * this.witnessSize;
        const hex2 = len2.toString(16).padStart(16, "0");
        buff32[pos] = parseInt(hex2.slice(0, 8), 16);
        buff32[pos + 1] = parseInt(hex2.slice(8), 16);
       function qualify_input(prefix, input, out) {
    if (Array.isArray(input)) {
        const flat = flatArray(input);
        if (flat.length === 0) {
            out[prefix] = [];
            return;
       _input(`${prefix}[${i}]`, input[i], out);
            }
        } else {
            out[prefix] = input;
        }
        return;
    }

    if (typeof input === "object") {
        for (const k of Object.keys(input)) {
            const np = prefix ? `${prefix}.${k}` : k;
            qualify_input(np, input[k], out);
        }
        return;
    }

    out[prefix] = input;
}

function flatArray(a) {
    const res = [];
    (function fill(x) {
        if (Array.isArray(x)) x.forEach(fill);
        else res.push(x);
    })(a);
    return res;
}

function toArray32(n, size) {
    const radix = BigInt(0x100000000);
    const res = [];
    while (n) {
        res.unshift(Number(n % radix));
        n /= radix;
    }
    while (res.length < size) res.unshift(0);
    return res;
}

function fromArray32(arr) {
    const radix = BigInt(0x100000000);
    return arr.reduce((acc, v) => acc * radix + BigInt(v), BigInt(0));
}

function normalize(n, prime) {
    let r = BigInt(n) % prime;
    if (r < 0n) r += prime;
    return r;
}

function fnvHash(str) {
    const max = 2n ** 64n;
    let hash = 0xcbf29ce484222325n;
    for (let i = 0; i < str.length; i++) {
        hash ^= BigInt(str.charCodeAt(i));
        hash = (hash * 0x100000001b3n) % max;
    }
    return hash.toString(16).padStart(16, "0");
}
