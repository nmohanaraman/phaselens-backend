/* PhaseLens auth-flow harness — drives the REAL index.html in jsdom with a
   mocked Firebase. Exists because three consecutive auth bugs (SDK race,
   error-wipe ordering, stuck button) were SEQUENCING bugs invisible to
   static checks. Run: node test_auth_flows.js  (exit 1 on any failure). */
const fs = require("fs");
const path = require("path");
const { JSDOM } = require(path.join("/home/claude/authtest", "node_modules", "jsdom"));

const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8")
  // strip the real firebase CDN tags — we inject a mock instead
  .replace(/<script src="https:\/\/www\.gstatic\.com[^"]*"><\/script>/g, "");

let PASS = 0, FAIL = 0;
const check = (name, cond, detail) => {
  if (cond) { PASS++; console.log("  [PASS] " + name); }
  else { FAIL++; console.log("  [FAIL] " + name + (detail ? " :: " + detail : "")); }
};

function makeDom({ fb, fetchImpl }) {
  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    url: "https://phaselens.ai/",
    beforeParse(window) {
      window.firebase = fb;
      window.fetch = fetchImpl || (async () => ({ json: async () => ({}) }));
      window.prompt = () => null;
      // jsdom can't navigate; spy instead
      window._nav = [];
      window.location.replace = (u) => window._nav.push(u);
      window.location.assign  = (u) => window._nav.push(u);
    },
  });
  return dom.window;
}

const okAuth = (overrides = {}) => ({
  onAuthStateChanged(cb) { this._cb = cb; },
  createUserWithEmailAndPassword: async () => ({ user: { sendEmailVerification: async () => {} } }),
  signInWithEmailAndPassword: async () => ({ user: {} }),
  sendPasswordResetEmail: async () => {},
  sendSignInLinkToEmail: async () => {},
  isSignInWithEmailLink: () => false,
  signOut: async function () { this._signedOut = true; },
  ...overrides,
});
const fbWith = (auth) => ({ initializeApp: () => ({}), auth: () => auth });
const rej = (code) => async () => { const e = new Error(code); e.code = code; throw e; };
const validCodeFetch = async (url) => ({
  json: async () => String(url).includes("access/validate")
    ? (String(url).toUpperCase().includes("FOUNDER2026")
        ? { valid: true, plan: "founder", label: "Founding Member", expires: "2027-07-17" }
        : { valid: false })
    : {},
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function fill(w, { email, pass, confirm, code, terms }) {
  if (email  !== undefined) w.document.getElementById("ae").value = email;
  if (pass   !== undefined) { w.document.getElementById("ap").value = pass; w.ck(); }
  if (confirm !== undefined) { w.document.getElementById("ac").value = confirm; w.cm && w.cm(); }
  if (code   !== undefined) w.document.getElementById("acode").value = code;
  if (terms) w.ta();
}
const eb = (w) => ({ shown: w.document.getElementById("eb").style.display === "block",
                     text: w.document.getElementById("eb").textContent });
const btn = (w) => ({ text: w.document.getElementById("sb").textContent,
                      disabled: w.document.getElementById("sb").disabled });

(async () => {
  console.log("=== AUTH FLOW HARNESS (real DOM, mocked Firebase) ===");

  // 1. Signup happy path
  {
    const w = makeDom({ fb: fbWith(okAuth()), fetchImpl: validCodeFetch });
    await sleep(30);
    w._entered = []; w.goDash = (u) => w._entered.push(u);   // jsdom can't navigate; spy the entry fn
    w.openAuth(false);
    fill(w, { email: "new@x.com", pass: "longenough8", confirm: "longenough8", code: "FOUNDER2026", terms: true });
    await w.doAuth(); await sleep(20);
    check("signup: enters the app (goDash called)", w._entered.length === 1);
    check("signup: founder entitlement stored", (w.localStorage.getItem("pl_plan") || "").includes("founder"));
    check("signup: verification notice queued", (w.sessionStorage.getItem("pl_notice") || "").includes("Verification"));
  }

  // 2. Signup with existing email — must SHOW error and restore button
  {
    const w = makeDom({ fb: fbWith(okAuth({ createUserWithEmailAndPassword: rej("auth/email-already-in-use") })), fetchImpl: validCodeFetch });
    await sleep(30); w.openAuth(false);
    fill(w, { email: "dup@x.com", pass: "longenough8", confirm: "longenough8", code: "FOUNDER2026", terms: true });
    await w.doAuth(); await sleep(20);
    const e = eb(w), b = btn(w);
    check("dup email: error VISIBLE", e.shown && e.text.includes("already exists"), e.text);
    check("dup email: button restored (not stuck Authenticating)", !b.disabled && !b.text.includes("Authenticating"), b.text);
    check("dup email: _holdRedirect released", w._holdRedirect === false);
  }

  // 3. Sign-in wrong password — the reported bug
  {
    const w = makeDom({ fb: fbWith(okAuth({ signInWithEmailAndPassword: rej("auth/wrong-password") })) });
    await sleep(30); w.openAuth(true);
    fill(w, { email: "me@x.com", pass: "wrongpass1" });
    await w.doAuth(); await sleep(20);
    const e = eb(w), b = btn(w);
    check("wrong pass: error VISIBLE", e.shown && e.text.includes("Incorrect password"), e.text);
    check("wrong pass: button restored to 'Sign In'", !b.disabled && b.text === "Sign In", b.text);
  }

  // 4. Sign-in invalid-credential (Firebase's newer generic code)
  {
    const w = makeDom({ fb: fbWith(okAuth({ signInWithEmailAndPassword: rej("auth/invalid-credential") })) });
    await sleep(30); w.openAuth(true);
    fill(w, { email: "me@x.com", pass: "wrongpass1" });
    await w.doAuth(); await sleep(20);
    check("invalid-credential: mapped + visible", eb(w).shown && eb(w).text.includes("Invalid email or password"));
  }

  // 5. Password reset — success and unknown email
  {
    const w = makeDom({ fb: fbWith(okAuth()) });
    await sleep(30); w.openAuth(true);
    fill(w, { email: "me@x.com" });
    w.doReset(); await sleep(20);
    check("reset: green confirmation shown", eb(w).shown && eb(w).text.includes("reset link sent"), eb(w).text);
  }
  {
    const w = makeDom({ fb: fbWith(okAuth({ sendPasswordResetEmail: rej("auth/user-not-found") })) });
    await sleep(30); w.openAuth(true);
    fill(w, { email: "ghost@x.com" });
    w.doReset(); await sleep(20);
    check("reset unknown email: actionable error", eb(w).shown && eb(w).text.includes("No account found"));
  }
  {
    const w = makeDom({ fb: fbWith(okAuth()) });
    await sleep(30); w.openAuth(true);
    w.doReset(); await sleep(10);
    check("reset with empty email: asks for email first", eb(w).shown && eb(w).text.includes("Enter your email"));
  }

  // 6. Invite code gate
  {
    const w = makeDom({ fb: fbWith(okAuth()), fetchImpl: validCodeFetch });
    await sleep(30); w.openAuth(false);
    fill(w, { email: "n@x.com", pass: "longenough8", confirm: "longenough8", code: "WRONG", terms: true });
    await w.doAuth(); await sleep(20);
    check("bad invite code: rejected with message", eb(w).shown && eb(w).text.includes("invite code"), eb(w).text);
    check("bad invite code: no account created / no nav", w._nav.length === 0 && !(w._entered||[]).length);
  }
  {
    const w = makeDom({ fb: fbWith(okAuth()), fetchImpl: validCodeFetch });
    await sleep(30); w.openAuth(false);
    fill(w, { email: "n@x.com", pass: "longenough8", confirm: "longenough8", terms: true });
    await w.doAuth(); await sleep(20);
    check("missing invite code: explicit message", eb(w).shown && eb(w).text.includes("private beta"));
  }

  // 7. Pre-check messages (short password / mismatch / terms)
  {
    const w = makeDom({ fb: fbWith(okAuth()), fetchImpl: validCodeFetch });
    await sleep(30); w.openAuth(false);
    fill(w, { email: "n@x.com", pass: "short" });
    await w.doAuth();
    check("short password: explicit count message", eb(w).text.includes("at least 8 characters (currently 5)"), eb(w).text);
    fill(w, { pass: "longenough8", confirm: "different8" });
    await w.doAuth();
    check("mismatch: explicit message", eb(w).text.includes("do not match"));
    fill(w, { confirm: "longenough8" });
    await w.doAuth();
    check("terms unticked: explicit message", eb(w).text.includes("agreement checkbox"));
  }

  // 8. Sign-out flag: landing must sign out Firebase and NOT bounce back
  {
    const auth = okAuth();
    const w = makeDom({ fb: fbWith(auth) });
    w.sessionStorage.setItem("pl_signout", "1");
    await sleep(30);
    w.initFB();
    auth._cb && auth._cb({ email: "me@x.com" });   // persisted-user event fires
    await sleep(10);
    check("signout flag: firebase signOut called", auth._signedOut === true);
    check("signout flag: consumed", w.sessionStorage.getItem("pl_signout") === null);
    check("signout flag: NO bounce to app", !w._nav.some((u) => String(u).includes("app.html")), JSON.stringify(w._nav));
  }

  // 9. Normal persisted user still auto-enters the app
  {
    const auth = okAuth();
    const w = makeDom({ fb: fbWith(auth) });
    await sleep(30);
    w._entered = []; w.goDash = (u) => w._entered.push(u);
    w.initFB();
    auth._cb && auth._cb({ email: "me@x.com", displayName: "M", uid: "u1" });
    await sleep(10);
    check("persisted user: auto-redirect to app intact", w._entered.length === 1);
  }

  // 10. SDK never loads: page must not crash; sign-in click explains
  {
    const w = makeDom({ fb: undefined });
    await sleep(30);
    let threw = false;
    try { w.openAuth(true); fill(w, { email: "a@x.com", pass: "longenough8" }); await w.doAuth(); }
    catch (e) { threw = true; }
    await sleep(20);
    check("no SDK: no crash", !threw);
    check("no SDK: user told what's happening", eb(w).shown, eb(w).text);
  }

  console.log("\nAUTH FLOWS: " + PASS + " passed, " + FAIL + " failed");
  process.exit(FAIL ? 1 : 0);
})();
