pragma circom 2.2.3;

include "circomlib/circuits/bitify.circom";
include "keccak256-circom/circuits/keccak.circom";

template DidProofKnowledge(S_BYTES, DID_BYTES) {
    // ---- INPUTS ----
    // Privato: S (segretto) in bytes [0..255]
    signal input S[S_BYTES];

    // Pubblico: DID in bytes (stessa codifica/padding del JS)
    signal input DID[DID_BYTES];

    // Pubblico: V come 256 bit (digest keccak-256)
    signal input V[256];

     signal output hashComputed[256];

    // ---- Byte -> Bit ----
    component s2b[S_BYTES];
    component d2b[DID_BYTES];

    // bit array per S||DID
    signal inBits[(S_BYTES + DID_BYTES) * 8];

    // S in bit (LSB-first per byte come Num2Bits)
    for (var i = 0; i < S_BYTES; i++) {
        s2b[i] = Num2Bits(8);
        s2b[i].in <== S[i];
        for (var j = 0; j < 8; j++) {
            inBits[i*8 + j] <== s2b[i].out[j];
        }
    }

    // DID in bit
    for (var k = 0; k < DID_BYTES; k++) {
        d2b[k] = Num2Bits(8);
        d2b[k].in <== DID[k];
        for (var j2 = 0; j2 < 8; j2++) {
            inBits[S_BYTES*8 + k*8 + j2] <== d2b[k].out[j2];
        }
    }

    // ---- Keccak256(S||DID) ----
    component keccak = Keccak((S_BYTES + DID_BYTES) * 8, 256);
    for (var b = 0; b < (S_BYTES + DID_BYTES) * 8; b++) {
        keccak.in[b] <== inBits[b];
    }

    // ---- Vincolo di uguaglianza dell’hash ----
    for (var h = 0; h < 256; h++) {
        keccak.out[h] === V[h];
    }

   for (var x = 0; x < 256; x++) { hashComputed[x] <== keccak.out[x]; }
}

// Istanza principale: imposta le lunghezze fisse
component main {public [DID,V]} = DidProofKnowledge(64, 64); // 32B S, 64B DID
