import React, { useState, useEffect, useRef } from "react";
import init, { derive_path } from "../pkg/cardano_ed25519.js";

// Every byte on this page comes from the Rust crate compiled to WebAssembly
// (src/wasm.rs). There is deliberately no JavaScript cryptography here: the
// explorer and `cargo run` call the same code, so they cannot disagree.

const DEFAULT_PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const DEFAULT_PATH = "m/1852'/1815'/0'/0/0";
const DEFAULT_MESSAGE = "Hello, Cardano!";
// Pre-filled with the signed message plus one byte, so the page opens on a
// failing verification. Edit it to match and the check flips to green.
const DEFAULT_VERIFY_MESSAGE = "Hello, Cardano!!";

export default function CardanoKeyExplorer() {
  const [phrase, setPhrase] = useState(DEFAULT_PHRASE);
  const [passphrase, setPassphrase] = useState("");
  const [path, setPath] = useState(DEFAULT_PATH);
  const [message, setMessage] = useState(DEFAULT_MESSAGE);
  const [verifyMessage, setVerifyMessage] = useState(DEFAULT_VERIFY_MESSAGE);

  const [ready, setReady] = useState(false);
  const [result, setResult] = useState(null);
  const [activeIdx, setActiveIdx] = useState(0);
  const [error, setError] = useState("");

  // Keep the selected tree node pinned to the leaf only while the user has
  // not picked one, so re-deriving does not yank the panel away from them.
  const pinnedToLeaf = useRef(true);

  useEffect(() => {
    init()
      .then(() => setReady(true))
      .catch((e) => setError(`Failed to load WebAssembly module: ${e}`));
  }, []);

  useEffect(() => {
    if (!ready) return;
    try {
      const parsed = JSON.parse(
        derive_path(phrase, passphrase, path, message, verifyMessage)
      );
      setResult(parsed);
      setError("");
      setActiveIdx((prev) =>
        pinnedToLeaf.current ? parsed.nodes.length - 1 : Math.min(prev, parsed.nodes.length - 1)
      );
    } catch (e) {
      setError(e?.message ?? String(e));
      setResult(null);
    }
  }, [ready, phrase, passphrase, path, message, verifyMessage]);

  const nodes = result?.nodes ?? [];
  const active = nodes[activeIdx];

  return (
    <div style={S.page}>
      <header style={S.header}>
        <h1 style={S.title}>BIP32-Ed25519 - Key Derivation</h1>
        <p style={S.subtitle}>
          The page runs in two steps. First, derivation: a mnemonic becomes a
          root key, and each segment of the path derives a child key from its
          parent. Second, signing: the key at the end of the path signs a
          message, and its public key verifies the signature.
        </p>
      </header>

      <Step
        n={1}
        title="Derive the key"
        hint="The mnemonic and passphrase produce the root key m. Each path segment derives one child from its parent, so the leaf key depends on every segment before it. Click a node in the tree to read its keys."
      />

      <section style={S.controls}>
        <Field label="Mnemonic (BIP-39 test vector)">
          <textarea
            style={{ ...S.input, resize: "vertical", minHeight: "56px" }}
            value={phrase}
            onChange={(e) => setPhrase(e.target.value)}
            spellCheck={false}
          />
        </Field>
        <div style={S.row}>
          <Field label="Passphrase (optional)" grow>
            <input
              style={S.input}
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="(empty)"
              spellCheck={false}
            />
          </Field>
          <Field label="Derivation path" grow>
            <input
              style={S.input}
              value={path}
              onChange={(e) => setPath(e.target.value)}
              spellCheck={false}
            />
          </Field>
        </div>
      </section>

      {!ready && !error && <div style={S.dim}>Loading WebAssembly module…</div>}
      {error && <div style={S.errorBox}>{error}</div>}

      {nodes.length > 0 && (
        <>
          <div style={S.treeRow}>
            {nodes.map((n, i) => (
              <React.Fragment key={i}>
                {i > 0 && <div style={S.connector} />}
                <button
                  onClick={() => {
                    pinnedToLeaf.current = i === nodes.length - 1;
                    setActiveIdx(i);
                  }}
                  style={{
                    ...S.node,
                    ...(i === activeIdx ? S.nodeActive : {}),
                    ...(i > 0 && !n.hardened ? S.nodeSoft : {}),
                  }}
                  title={i === 0 ? "root" : n.hardened ? "hardened" : "soft"}
                >
                  {n.label}
                </button>
              </React.Fragment>
            ))}
          </div>

          <div style={S.panel}>
            <div style={S.panelTitle}>
              <span>{active.label}</span>
              {activeIdx > 0 && (
                <span style={active.hardened ? S.badgeHard : S.badgeSoft}>
                  {active.hardened ? "hardened" : "soft"}
                </span>
              )}
            </div>
            <HexRow label="kL — signing scalar (clamped)" value={active.kl} />
            <HexRow label="kR — nonce material" value={active.kr} />
            <HexRow label="chain code" value={active.chain_code} />
            <HexRow label="public key A = [kL]B" value={active.public_key} accent />
          </div>

          <Step
            n={2}
            title="Sign and verify with the derived key"
            hint="The leaf key from step 1 signs the first message. The signature is then checked against the second one — change a single byte there to watch verification fail."
          />

          <div style={S.panel}>
            <div style={S.row}>
              <Field label="Message to sign with the leaf key" grow>
                <input
                  style={S.input}
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  spellCheck={false}
                />
              </Field>
              <Field label="Message to verify against" grow>
                <input
                  style={S.input}
                  value={verifyMessage}
                  onChange={(e) => setVerifyMessage(e.target.value)}
                  spellCheck={false}
                />
              </Field>
            </div>
            <HexRow label={`Ed25519 signature over "${result.signature.message}"`} value={result.signature.signature} accent />
            <div style={S.checks}>
              <Check ok={result.signature.valid} label="Verifies against the signed message" />
              {/* Shows the verification result itself, so a rejected message
                  reads red even though rejecting it is the correct outcome. */}
              <Check
                ok={result.signature.verify_valid}
                label={
                  result.signature.verify_valid
                    ? "Second message is identical — signature verifies"
                    : "Second message differs — signature rejected"
                }
              />
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Step({ n, title, hint }) {
  return (
    <div style={S.step}>
      <div style={S.stepTitle}>
        <span style={S.stepNumber}>{n}</span>
        {title}
      </div>
      {hint && <div style={S.stepHint}>{hint}</div>}
    </div>
  );
}

function Field({ label, children, grow }) {
  return (
    <label style={{ ...S.label, ...(grow ? { flex: 1, minWidth: "200px" } : {}) }}>
      {label}
      {children}
    </label>
  );
}

function HexRow({ label, value, accent }) {
  return (
    <div style={S.hexRow}>
      <div style={S.hexLabel}>{label}</div>
      <div style={{ ...S.hexValue, color: accent ? "#7fe3d4" : "#c7d4de" }}>{value}</div>
    </div>
  );
}

function Check({ ok, label }) {
  return (
    <div style={{ ...S.check, color: ok ? "#5fd4c4" : "#ff9b9b" }}>
      <span aria-hidden="true">{ok ? "✓" : "✗"}</span> {label}
    </div>
  );
}

const mono = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";

const S = {
  page: {
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
    background: "#0f1720",
    color: "#e7edf3",
    padding: "32px",
    borderRadius: "12px",
    maxWidth: "820px",
    margin: "24px auto",
    boxSizing: "border-box",
  },
  header: { marginBottom: "24px" },
  kicker: { color: "#5fd4c4", fontSize: "14px", letterSpacing: "0.04em", marginBottom: "6px" },
  title: { color: "#5fd4c4", fontSize: "28px", fontWeight: 700, margin: "0 0 8px 0" },
  subtitle: { color: "#9fb0bf", fontSize: "14px", lineHeight: 1.6, margin: 0, maxWidth: "620px" },
  controls: { display: "flex", flexDirection: "column", gap: "14px", marginBottom: "20px" },
  row: { display: "flex", gap: "14px", flexWrap: "wrap" },
  label: { display: "flex", flexDirection: "column", gap: "6px", fontSize: "12px", color: "#9fb0bf" },
  input: {
    fontFamily: mono,
    fontSize: "13px",
    padding: "10px 12px",
    borderRadius: "8px",
    border: "1px solid #263341",
    background: "#141d27",
    color: "#e7edf3",
    outline: "none",
    width: "100%",
    boxSizing: "border-box",
  },
  errorBox: {
    background: "#3a1c1c",
    border: "1px solid #6b2b2b",
    color: "#ffb4b4",
    padding: "10px 12px",
    borderRadius: "8px",
    fontSize: "13px",
    marginBottom: "16px",
    fontFamily: mono,
  },
  treeRow: { display: "flex", alignItems: "center", flexWrap: "wrap", marginBottom: "20px" },
  connector: { width: "18px", height: "1px", background: "#2c3b4a", margin: "0 2px" },
  node: {
    fontFamily: mono,
    fontSize: "12px",
    padding: "8px 12px",
    borderRadius: "8px",
    border: "1px solid #263341",
    background: "#141d27",
    color: "#c7d4de",
    cursor: "pointer",
  },
  nodeActive: { borderColor: "#5fd4c4", color: "#5fd4c4", background: "#132420" },
  nodeSoft: { borderStyle: "dashed" },
  panel: {
    background: "#141d27",
    border: "1px solid #263341",
    borderRadius: "10px",
    padding: "20px",
    marginBottom: "16px",
    display: "flex",
    flexDirection: "column",
    gap: "12px",
  },
  step: { display: "flex", flexDirection: "column", gap: "6px", margin: "24px 0 14px" },
  stepTitle: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    fontSize: "15px",
    fontWeight: 600,
  },
  stepNumber: {
    fontFamily: mono,
    fontSize: "11px",
    width: "22px",
    height: "22px",
    borderRadius: "999px",
    border: "1px solid #2c4b46",
    color: "#5fd4c4",
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
  },
  stepHint: { color: "#7d90a0", fontSize: "12px", lineHeight: 1.6, maxWidth: "620px" },
  panelTitle: {
    fontFamily: mono,
    fontSize: "14px",
    display: "flex",
    alignItems: "center",
    gap: "10px",
  },
  badgeHard: {
    fontSize: "10px",
    color: "#5fd4c4",
    border: "1px solid #24463f",
    borderRadius: "999px",
    padding: "2px 8px",
  },
  badgeSoft: {
    fontSize: "10px",
    color: "#e8b563",
    border: "1px solid #4a3a1f",
    borderRadius: "999px",
    padding: "2px 8px",
  },
  dim: { color: "#8296a5", fontSize: "13px", lineHeight: 1.6 },
  hexRow: { display: "flex", flexDirection: "column", gap: "4px" },
  hexLabel: { fontSize: "11px", color: "#7d90a0" },
  hexValue: { fontFamily: mono, fontSize: "12px", wordBreak: "break-all", lineHeight: 1.5 },
  checks: { display: "flex", flexDirection: "column", gap: "6px", fontSize: "12px" },
  check: { fontFamily: mono },
  footnote: { color: "#7d90a0", fontSize: "12px", lineHeight: 1.7, marginTop: "8px" },
  code: { fontFamily: mono, background: "#1c2836", padding: "1px 5px", borderRadius: "4px" },
};
