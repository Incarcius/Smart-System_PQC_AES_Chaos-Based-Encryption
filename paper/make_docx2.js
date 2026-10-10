// Second paper, built to the SmartMediQ template.
//
// Differences from the IEEE conference build: A4 rather than Letter, 50 pt
// margins, 9 pt Times body, a five author grid in the title block, six large
// numbered sections, and figure and table captions in the "Figure 1." and
// "Table I." style that paper uses.
//
// House rule carried over: no em dashes and no en dashes anywhere.

const fs = require("fs");
const path = require("path");
const {
  AlignmentType, BorderStyle, Document, ImageRun, Packer, Paragraph,
  SectionType, Table, TableCell, TableRow, TabStopType, TextRun, WidthType,
} = require("docx");

const HERE = __dirname;
const OUT = path.join(HERE, "PQC_IIoT_Grid_SystemPaper.docx");

const FONT = "Times New Roman";
const A4 = { width: 11906, height: 16838 };          // DXA
const MARGIN = { top: 1000, bottom: 1100, left: 1000, right: 1000 };
const GUTTER = 280;
const COL_DXA = Math.floor((A4.width - 2000 - GUTTER) / 2);

const BODY_SZ = 18;   // 9 pt, in half points

// ── helpers ────────────────────────────────────────────────────────────────
const run = (text, o = {}) =>
  new TextRun({ text, font: FONT, size: o.size ?? BODY_SZ, bold: o.bold,
                italics: o.italics, superScript: o.sup });

const body = (t, o = {}) =>
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { line: 220, lineRule: "auto", after: o.after ?? 90 },
    indent: { firstLine: o.noIndent ? 0 : 0 },
    children: (Array.isArray(t) ? t : [{ t }]).map((f) =>
      run(f.t, { italics: f.i, bold: f.b, sup: f.sup })),
  });

const bullet = (t) =>
  new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { line: 220, lineRule: "auto", after: 50 },
    indent: { left: 260, hanging: 150 },
    children: (Array.isArray(t) ? t : [{ t }]).map((f) =>
      run(f.t, { italics: f.i, bold: f.b })),
  });

const section = (num, title) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 220, after: 110 },
    keepNext: true,
    children: [run(num ? `${num}.  ${title.toUpperCase()}` : title.toUpperCase(),
                   { size: 19, bold: true })],
  });

const subsection = (ltr, title) =>
  new Paragraph({
    alignment: AlignmentType.LEFT,
    spacing: { before: 140, after: 70 },
    keepNext: true,
    children: [run(`${ltr}. ${title}`, { size: 18, bold: true })],
  });

const caption = (text) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 90, after: 170 },
    children: Array.isArray(text)
      ? text.map((f) => run(f.t, { size: 16, italics: f.i, bold: f.b }))
      : [run(text, { size: 16, italics: true })],
  });

const figure = (name, w, h) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 150, after: 0 },
    keepNext: true,
    children: [new ImageRun({
      type: "png",
      data: fs.readFileSync(path.join(HERE, name)),
      transformation: { width: w, height: h },
    })],
  });

const gap = (h) => new Paragraph({ spacing: { after: h }, children: [] });

// ── tables ─────────────────────────────────────────────────────────────────
const LINE = { style: BorderStyle.SINGLE, size: 4, color: "000000" };
const cell = (text, o = {}) =>
  new TableCell({
    width: { size: o.w, type: WidthType.DXA },
    margins: { top: 40, bottom: 40, left: 70, right: 70 },
    borders: { top: LINE, bottom: LINE, left: LINE, right: LINE },
    children: [new Paragraph({
      alignment: o.right ? AlignmentType.RIGHT : AlignmentType.LEFT,
      spacing: { after: 0, line: 200, lineRule: "auto" },
      keepNext: o.keepNext,
      children: [run(text, { size: 16, bold: o.bold, italics: o.italics })],
    })],
  });

function gridTable(colW, header, rows) {
  return new Table({
    columnWidths: colW,
    width: { size: colW.reduce((a, b) => a + b, 0), type: WidthType.DXA },
    rows: [
      new TableRow({
        tableHeader: true,
        children: header.map((h, i) =>
          cell(h, { w: colW[i], bold: true, keepNext: true })),
      }),
      ...rows.map((r, ri) =>
        new TableRow({
          children: r.map((c, i) =>
            cell(c, { w: colW[i], right: i > 0 && /^[-0-9]/.test(c),
                      keepNext: ri < rows.length - 1 })),
        })),
    ],
  });
}

const tableCaption = (n, text) =>
  new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { before: 170, after: 80 },
    keepNext: true,
    children: [run(`Table ${n}. `, { size: 16, bold: true }),
               run(text, { size: 16, italics: true })],
  });

// ── title block ────────────────────────────────────────────────────────────
const TITLE_LINES = [
  "A Post-Quantum Secured Industrial IoT Telemetry",
  "Architecture with Learned Key Lifecycle Control and",
  "Adaptive Chaotic Masking for Power Grids",
];

const AUTHORS = [
  ["Guide Name", "Department", "Institute Name", "City, State, India", "email"],
  ["Author Two", "Department", "Institute Name", "City, State, India", "email"],
  ["Author Three", "Department", "Institute Name", "City, State, India", "email"],
  ["Author Four", "Department", "Institute Name", "City, State, India", "email"],
  ["Author Five", "Department", "Institute Name", "City, State, India", "email"],
];

function authorGrid() {
  const full = A4.width - 2000;
  const w = Math.floor(full / 5);
  const widths = [w, w, w, w, full - 4 * w];
  const NOB = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };
  const mk = (txt, i, bold) =>
    new TableCell({
      width: { size: widths[i], type: WidthType.DXA },
      margins: { top: 10, bottom: 10, left: 40, right: 40 },
      borders: { top: NOB, bottom: NOB, left: NOB, right: NOB },
      children: [new Paragraph({
        alignment: AlignmentType.CENTER,
        spacing: { after: 0, line: 200, lineRule: "auto" },
        children: [run(txt, { size: 17, bold })],
      })],
    });
  const rows = [];
  for (let r = 0; r < 5; r++) {
    rows.push(new TableRow({
      children: AUTHORS.map((a, i) => mk(a[r], i, r === 0)),
    }));
  }
  return new Table({ columnWidths: widths, rows,
                     width: { size: full, type: WidthType.DXA } });
}

const titleBlock = [
  ...TITLE_LINES.map((t, i) => new Paragraph({
    alignment: AlignmentType.CENTER,
    spacing: { after: i === TITLE_LINES.length - 1 ? 200 : 0 },
    children: [run(t, { size: 30, bold: true })],
  })),
  authorGrid(),
  gap(180),
];

// ── body ───────────────────────────────────────────────────────────────────
const B = require("./content2.js")({
  body, bullet, section, subsection, caption, figure, gap, gridTable,
  tableCaption, COL_DXA,
});

// ── references ─────────────────────────────────────────────────────────────
B.push(section(null, "References"));
const REFS = require("./refs2.js");
REFS.forEach((r, i) => {
  B.push(new Paragraph({
    alignment: AlignmentType.JUSTIFIED,
    spacing: { line: 200, lineRule: "auto", after: 40 },
    indent: { left: 380, hanging: 380 },
    tabStops: [{ type: TabStopType.LEFT, position: 380 }],
    children: [run(`[${i + 1}]\t${r}`, { size: 16 })],
  }));
});

// ── assemble ───────────────────────────────────────────────────────────────
const doc = new Document({
  creator: "IPD Group 9",
  title: TITLE_LINES.join(" "),
  description: "System paper, SmartMediQ template.",
  styles: { default: { document: { run: { font: FONT, size: BODY_SZ } } } },
  sections: [
    { properties: { page: { size: A4, margin: MARGIN } }, children: titleBlock },
    { properties: {
        type: SectionType.CONTINUOUS,
        page: { size: A4, margin: MARGIN },
        column: { count: 2, space: GUTTER, equalWidth: true },
      },
      children: B },
    { properties: {
        type: SectionType.CONTINUOUS,
        page: { size: A4, margin: MARGIN },
        column: { count: 1 },
      },
      children: [new Paragraph({ spacing: { after: 0 }, children: [] })] },
  ],
});

Packer.toBuffer(doc).then((buf) => {
  fs.writeFileSync(OUT, buf);
  console.log("wrote " + OUT + " (" + (buf.length / 1024).toFixed(0) + " KB)");
});
