// Reads {"input": {...}} on stdin, writes {"proof": {...}, "publicSignals": [...]} on stdout.
// The witness (including the secret key) never touches the filesystem.
const path = require("path");
const snarkjs = require("snarkjs");
const build = path.join(__dirname, "build");

let data = "";
process.stdin.on("data", (c) => (data += c));
process.stdin.on("end", async () => {
  try {
    const { input } = JSON.parse(data);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      path.join(build, "session_auth.wasm"),
      path.join(build, "session_auth.zkey")
    );
    process.stdout.write(JSON.stringify({ proof, publicSignals }));
    process.exit(0);
  } catch (e) {
    process.stderr.write(String(e && e.message ? e.message : e));
    process.exit(1);
  }
});
