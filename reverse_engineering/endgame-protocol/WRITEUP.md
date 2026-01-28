# Endgame Protocol — Writeup

## Overview

This challenge combines web exploitation with reverse engineering.
The server never reveals the flag directly.

Instead, it applies a reversible transformation.

---

## Step 1: Trigger the Snap

Clicking the button sends a request to `/snap`,
which returns unreadable output.

---

## Step 2: Inspect Client-Side Code

The JavaScript file `protocol.min.js` contains
the transformation logic used by the server.

---

## Step 3: Reverse the Algorithm

The function applies:
- XOR with index
- modulo arithmetic
- character shifting

Reversing these steps recovers the original input.

---

## Step 4: Decode the Output

Applying the inverse transformation reveals:

DSCCTF{th3_r34l_3ndg4m3_w45_th3_pr0t0c0l_2026}


---

## Final Flag

DSCCTF{th3_r34l_3ndg4m3_w45_th3_pr0t0c0l_2026}


---

## Takeaway

- Not all web challenges are about bypassing auth
- Client-side code is part of the attack surface
- Reversing protocols is as important as breaking servers



## alternate solution found
paste in web console

function undo_p(r) {
  let o = "";
  for (let i = 0; i < r.length; i++) {
    o += String.fromCharCode((r.charCodeAt(i) - 1) ^ (i % 42));
  }
  return o;
}

var snap = "ESBAQD~ta;Vz@:cQ$wu!y&Ip.0Eiv.AQT\u0013X\u0015G\u0017Lx\u001c145\u007f";

console.log(undo_p(snap));
