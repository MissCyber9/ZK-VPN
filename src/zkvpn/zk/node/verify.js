// Reads {"proof": {...}, "publicSignals": [...]} on stdin; exit 0 and print "true"/"false".
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const vkey = JSON.parse(fs.readFileSync(path.join(__dirname, "build", "vkey.json"), "utf8"));

let data = "";
process.stdin.on("data", (c) => (data += c));
process.stdin.on("end", async () => {
  try {
    const { proof, publicSignals } = JSON.parse(data);
    const ok = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    process.stdout.write(ok ? "true" : "false");
    process.exit(0);
  } catch (e) {
    process.stderr.write(String(e && e.message ? e.message : e));
    process.exit(1);
  }
});
