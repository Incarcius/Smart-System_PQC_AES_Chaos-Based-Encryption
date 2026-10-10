// Build the IEEE-format paper as an editable .docx.
//
// Layout: US Letter, 0.62" side margins, Times New Roman throughout. Section 1
// is the full-width title block; section 2 is a CONTINUOUS break into two
// columns, which is how the IEEE template is structured.
//
// Prose lives in content.js. House rule for this draft: no em dashes and no en
// dashes anywhere, including in the references and numeric ranges.

const fs = require("fs");
const path = require("path");
const {
  AlignmentType, BorderStyle, Document, ImageRun, Packer, Paragraph,
  SectionType, Table, TableCell, TableRow, TabStopType, TextRun, WidthType,
} = require("docx");

const HERE = __dirname;
const OUT = path.join(HERE, "IEEE_PQC_IIoT_Telemetry.docx");
const FIG = path.join(HERE, "fig1_architecture.png");

const FONT = "Times New Roman";
const LETTER = { width: 12240, height: 15840 };              // DXA
const MARGIN = { top: 1080, bottom: 1224, left: 900, right: 900 };
const COL_DXA = Math.floor((12240 - 900 - 900 - 360) / 2);   // 3.5" columns

// ── helpers ────────────────────────────────────────────────────────────────
const run = (text, o = {}) =>
  new TextRun({ text, font: FONT, size: o.size ?? 19, bold: o.bold,
                italics: o.italics, superScript: o.sup });

const body = (t, o = {}) =>
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { line: 228, lineRule: "auto", after: 0 },
    indent: { firstLine: o.noIndent ? 0 : 170 },
    children: (Array.isArray(t) ? t : [{ t }]).map((f) =>
      run(f.t, { italics: f.i, bold: f.b, sup: f.sup })),
  });

const section = (num, title) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 190, after: 90 },
    keepNext: true,
    children: [run(num ? `${num}.  ${title.toUpperCase()}` : title.toUpperCase(),
                   { size: 20 })],
  });

const subsection = (ltr, title) =>
  new Paragraph({
    alignment: AlignmentType.LEFT,
    spacing: { before: 120, after: 60 },
    keepNext: true,
    children: [run(`${ltr}. ${title}`, { size: 19, italics: true })],
  });

const caption = (text) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 80, after: 160 },
    children: Array.isArray(text)
      ? text.map((f) => run(f.t, { size: 16, italics: f.i }))
      : [run(text, { size: 16 })],
  });

// `figure()` with no arguments is the architecture diagram; otherwise pass a
// file name and its placed size in pixels at 96 dpi.
const figure = (name, w, h) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 140, after: 0 },
    keepNext: true,
    children: [new ImageRun({
      type: "png",
      data: fs.readFileSync(name ? path.join(HERE, name) : FIG),
      transformation: { width: w || 326, height: h || 104 },
    })],
  });

const gap = (h) => new Paragraph({ spacing: { after: h }, children: [] });

// IEEE tables: rule above the header, hairline below it, rule under the body.
// keepNext holds the caption and the rows together so a short table does not
// straddle a column break.
const NB = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
const cell = (text, o = {}) =>
  new TableCell({
    width: { size: o.w, type: WidthType.DXA },
    margins: { top: 30, bottom: 30, left: 60, right: 60 },
    borders: { top: o.top ?? NB, bottom: o.bottom ?? NB, left: NB, right: NB },
    children: [new Paragraph({
      alignment: o.right ? AlignmentType.RIGHT : AlignmentType.LEFT,
      spacing: { after: 0, line: 200, lineRule: "auto" },
      keepNext: o.keepNext,
      children: [run(text, { size: 16, italics: o.italics, bold: o.bold })],
    })],
  });

function ieeeTable(colW, header, rows, boldFirstRow) {
  const RULE = { style: BorderStyle.SINGLE, size: 10, color: "000000" };
  const HAIR = { style: BorderStyle.SINGLE, size: 4, color: "000000" };
  return new Table({
    columnWidths: colW,
    width: { size: colW.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    rows: [
      new TableRow({
        children: header.map((h, i) =>
          cell(h, { w: colW[i], italics: true, right: i > 0, top: RULE,
                    bottom: HAIR, keepNext: true })),
      }),
      ...rows.map((r, ri) =>
        new TableRow({
          children: r.map((c, i) =>
            cell(c, {
              w: colW[i], right: i > 0,
              bold: boldFirstRow && ri === 0,
              keepNext: ri < rows.length - 1,
              bottom: ri === rows.length - 1 ? RULE : NB,
            })),
        })),
    ],
  });
}

const tableHead = (n) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 150, after: 50 },
    keepNext: true,
    children: [run(`TABLE ${n}`, { size: 16 })],
  });

const tableSub = (text) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: 70 },
    keepNext: true,
    children: [run(text, { size: 16, italics: true })],
  });

// ── title block (section 1, full width) ────────────────────────────────────
const TITLE = "An AI-Enhanced Post-Quantum Key Exchange with Chaotic Stream " +
              "Masking for Secure Power-Grid IIoT Telemetry";

const ABSTRACT =
  "Industrial IoT telemetry in electrical transmission must survive an " +
  "adversary who records traffic now and decrypts it once cryptographically " +
  "relevant quantum computers exist, and must keep operating when the control " +
  "channel itself is attacked. We present a three tier telemetry path, " +
  "comprising a constrained sensor node, a field gateway and a control server, " +
  "secured by an ML-KEM-512 and ML-DSA-44 root exchange, a custom extract and " +
  "expand key derivation function, AES-256-GCM under a deterministic 96 bit " +
  "nonce discipline, and an adaptive coupled chaotic masking layer applied " +
  "outside the authenticated encryption. Key lifecycle decisions are made by a " +
  "reinforcement learning agent trained against a parameterised detector " +
  "surrogate rather than a fixed detector, and anomaly scores come from an " +
  "LSTM autoencoder trained on benign traffic only. Against a threshold policy " +
  "the learned agent takes 74 percent fewer compromised steps while performing " +
  "76 percent fewer key rotations, winning on all 15 evaluation seeds and all " +
  "27 detector settings, and it continues to win in a disturbance regime " +
  "outside its training grid. We also report five measurement failures that " +
  "each produced a plausible but wrong result: a chaos only keystream that " +
  "passed at its nominal parameters and failed almost everywhere else, a " +
  "contradiction between the detector's calibration contract and the surrogate " +
  "the agent trained against that stayed invisible until both trained " +
  "components were connected, a randomness battery that fails six of twelve " +
  "tests on known good input at the sequence length used, a model selection " +
  "rule that performed worse than no selection, and a safety criterion that " +
  "could not have failed in the window it was measured in.";

const INDEX_TERMS =
  "post-quantum cryptography, industrial control systems, key management, " +
  "reinforcement learning, anomaly detection, SCADA security.";

const titleBlock = [
  new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 160 },
    children: [run(TITLE, { size: 40, bold: true })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 40 },
    children: [run("First Author, Second Author, Third Author, Fourth Author",
                   { size: 22 })],
  }),
  new Paragraph({
    alignment: AlignmentType.CENTER, spacing: { after: 220 },
    children: [run("Integrated Product Development, Group 9",
                   { size: 19, italics: true })],
  }),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { line: 220, lineRule: "auto", after: 110 },
    children: [
      run("Abstract", { size: 18, bold: true, italics: true }),
      run(": " + ABSTRACT, { size: 18, bold: true }),
    ],
  }),
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { line: 220, lineRule: "auto", after: 120 },
    children: [
      run("Index Terms", { size: 18, bold: true, italics: true }),
      run(": " + INDEX_TERMS, { size: 18, bold: true }),
    ],
  }),
];

// ── body ───────────────────────────────────────────────────────────────────
const B = require("./content.js")({
  body, section, subsection, caption, tableHead, tableSub, ieeeTable, gap,
  figure, COL_DXA,
});

// ── references ─────────────────────────────────────────────────────────────
B.push(section(null, "References"));
const REFS = [
  'National Institute of Standards and Technology, "Module-Lattice-Based Key-Encapsulation Mechanism Standard," FIPS 203, 2024.',
  'National Institute of Standards and Technology, "Module-Lattice-Based Digital Signature Standard," FIPS 204, 2024.',
  'S. Pan, T. Morris and U. Adhikari, "Developing a hybrid intrusion detection system using data mining for power systems," IEEE Trans. Smart Grid, vol. 6, no. 6, pp. 3104-3113, 2015.',
  'A. Rukhin et al., "A statistical test suite for random and pseudorandom number generators for cryptographic applications," NIST SP 800-22 Rev. 1a, 2010.',
  'H. van Hasselt, A. Guez and D. Silver, "Deep reinforcement learning with double Q-learning," in Proc. AAAI, 2016, pp. 2094-2100.',
  'Z. Wang et al., "Duelling network architectures for deep reinforcement learning," in Proc. ICML, 2016, pp. 1995-2003.',
  'R. M. Lee, M. J. Assante and T. Conway, "Analysis of the cyber attack on the Ukrainian power grid," E-ISAC and SANS ICS, Mar. 2016.',
  'M. Dworkin, "Recommendation for block cipher modes of operation: Galois/Counter Mode (GCM) and GMAC," NIST SP 800-38D, 2007.',
  'J. Kelsey, S. Chang and R. Perlner, "SHA-3 derived functions: cSHAKE, KMAC, TupleHash and ParallelHash," NIST SP 800-185, 2016.',
  'U. Adhikari, S. Pan, T. Morris, R. Borges and J. Beaver, "Industrial control system (ICS) cyber attack datasets," Mississippi State University and Oak Ridge National Laboratory, 2014.',
  'D. J. Bernstein, "Curve25519: New Diffie-Hellman speed records," in Proc. PKC, 2006, pp. 207-228.',
  'P. Malhotra, L. Vig, G. Shroff and P. Agarwal, "Long short term memory networks for anomaly detection in time series," in Proc. ESANN, 2015, pp. 89-94.',
  'H. Krawczyk and P. Eronen, "HMAC-based extract-and-expand key derivation function (HKDF)," RFC 5869, May 2010.',
  'X. Fang, L. Zheng, X. Fang, W. Chen, K. Fang, L. Yin and H. Zhu, "Pioneering advanced security solutions for reinforcement learning-based adaptive key rotation in Zigbee networks," Scientific Reports, vol. 14, art. 13931, 2024.',
];
REFS.forEach((r, i) => {
  B.push(new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { line: 200, lineRule: "auto", after: 30 },
    indent: { left: 380, hanging: 380 },
    tabStops: [{ type: TabStopType.LEFT, position: 380 }],
    children: [run(`[${i + 1}]\t${r}`, { size: 16 })],
  }));
});

// ── assemble ───────────────────────────────────────────────────────────────
const doc = new Document({
  creator: "IPD Group 9",
  title: TITLE,
  description: "IEEE-format conference draft.",
  styles: { default: { document: { run: { font: FONT, size: 19 } } } },
  sections: [
    { properties: { page: { size: LETTER, margin: MARGIN } },
      children: titleBlock },
    { properties: {
        type: SectionType.CONTINUOUS,
        page: { size: LETTER, margin: MARGIN },
        column: { count: 2, space: 360, equalWidth: true },
      },
      children: B },
    // A continuous break after the two-column run makes Word balance the final
    // page's columns. Without it the references fill the left column and the
    // right one is left empty, which is the standard untidy ending.
    { properties: {
        type: SectionType.CONTINUOUS,
        page: { size: LETTER, margin: MARGIN },
        column: { count: 1 },
      },
      children: [new Paragraph({ spacing: { after: 0 }, children: [] })] },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(OUT, buf);
  console.log("wrote " + OUT + " (" + (buf.length / 1024).toFixed(0) + " KB)");
});
