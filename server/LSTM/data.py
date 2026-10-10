"""data.py — loading and windowing for the anomaly detector.

Two data sources, one array shape
---------------------------------
The detector contract is `window: (T, F) float32`, and that is the only thing
the rest of the system knows about. Two very different sources produce it:

| source | F | native rate | role |
|---|---|---|---|
| MSU/ORNL power system | 128 | ~120 Hz, event-triggered | the paper's detection numbers |
| the rig | 5 channels x derived | 1 Hz | what actually gets deployed |

**These are two trained models, not one.** The MSU/ORNL data has 128 PMU and
relay features and no relationship to our five sensors, so weights cannot
transfer. What transfers is the *method* and this code path: train on normal
only, calibrate on held-out normal, score by reconstruction error. The public
dataset earns the evaluation (28 attack types, PR curves, detection delay) that
a rig with no labelled attacks could never produce; the rig model is trained
later with the same functions once there is rig-normal data to train on.

Saying this plainly matters because the obvious misreading -- "we trained an
LSTM on a public power-grid dataset and deployed it" -- would be false.

A note on the window and the sampling rate
------------------------------------------
REMAINING_WORK 3.2 specifies a "60 s window at 1 Hz". That is the *rig* case.
The MSU/ORNL rows are PMU samples at roughly 120 Hz captured around events, so
60 consecutive rows there span about half a second, not sixty. The window
length `T` is therefore in **rows**, and what a row means is a property of the
source. Both are legitimate; conflating them would silently change what
"detection delay" means, so `WindowSpec` carries the rate and the delay figures
are reported in seconds.
"""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from pathlib import Path

import numpy as np

# ---------------------------------------------------------------------------
# Scenario grouping
# ---------------------------------------------------------------------------
# The multiclass files label each row with a scenario number. 37 scenarios:
# 1 no-event, 8 natural disturbances, 28 attacks.
#
# The 8 natural disturbances are the whole reason this problem is non-trivial.
# A detector that flags every fault as an attack is useless in a control room,
# and the DQN's false-positive cost only means something if the detector
# actually produces false positives. They are the evaluation, not a nuisance.
#
# VERIFIED against PowerSystem_Dataset_README.pdf (Mississippi State / ORNL,
# 15 April 2014), which gives the natural set as "1,2,3,4,5,6,13,14" and the
# no-event set as "41":
#
#   1-6    short-circuit faults at points along lines L1 and L2
#   13,14  line maintenance (relays disabled deliberately)
#   41     normal operation with load changes
#
# Everything else is an attack: 7-12 fault with tripping command, 15-20
# command injection, 21-30 and 35-38 relay disabled plus fault, 39-40
# maintenance with relays disabled. Ids 31-34 do not occur. 8 + 28 + 1 = 37.
#
# `load_multiclass` still asserts the counts rather than trusting this table,
# because a silent mislabelling would corrupt every number downstream --
# natural events scored as attacks would flatter the detector precisely where
# it should be challenged.
NATURAL_SCENARIOS = frozenset({1, 2, 3, 4, 5, 6, 13, 14})
NO_EVENT_SCENARIOS = frozenset({41})

LABEL_NORMAL = 0
LABEL_NATURAL = 1
LABEL_ATTACK = 2

LABEL_NAMES = {LABEL_NORMAL: "no-event",
               LABEL_NATURAL: "natural",
               LABEL_ATTACK: "attack"}


def scenario_to_label(scenario: int) -> int:
    if scenario in NO_EVENT_SCENARIOS:
        return LABEL_NORMAL
    if scenario in NATURAL_SCENARIOS:
        return LABEL_NATURAL
    return LABEL_ATTACK


@dataclass(frozen=True)
class WindowSpec:
    """How rows become windows, and what a row means in wall-clock time."""

    length: int = 60
    stride: int = 10
    sample_hz: float = 1.0

    @property
    def seconds(self) -> float:
        return self.length / self.sample_hz

    def rows_to_seconds(self, rows: float) -> float:
        return rows / self.sample_hz


@dataclass
class Dataset:
    """Windowed data ready for the model.

    `X` is (N, T, F). `y` is (N,) in {LABEL_NORMAL, LABEL_NATURAL, LABEL_ATTACK}.
    `scenario` is (N,) raw scenario ids, kept for the per-scenario breakdown.
    `onset` is (N,) the row index within each window where the event begins, or
    -1 for windows with no event -- this is what detection delay is measured
    against, and it cannot be recovered later.
    """

    X: np.ndarray
    y: np.ndarray
    scenario: np.ndarray
    onset: np.ndarray
    spec: WindowSpec
    feature_names: list[str]
    attack_features: list[list[int]] | None = None
    """Which feature indices were corrupted, per window, where that is known.

    Aligned with `X` -- one entry per window, empty for windows with no
    injected fault. It has to travel inside the Dataset so that `subset`
    reindexes it alongside everything else: held as a separate list keyed by
    attack-window position, any split would silently pair each window with
    another window's ground truth, and attribution accuracy would be measured
    against the wrong answer without anything failing.
    """

    def __len__(self) -> int:
        return int(self.X.shape[0])

    @property
    def n_features(self) -> int:
        return int(self.X.shape[2])

    def subset(self, mask: np.ndarray) -> "Dataset":
        af = None
        if self.attack_features is not None:
            af = [self.attack_features[i] for i in np.flatnonzero(mask)]
        return Dataset(self.X[mask], self.y[mask], self.scenario[mask],
                       self.onset[mask], self.spec, self.feature_names, af)

    def counts(self) -> dict[str, int]:
        return {name: int((self.y == lab).sum())
                for lab, name in LABEL_NAMES.items()}


# ---------------------------------------------------------------------------
# Windowing
# ---------------------------------------------------------------------------

def make_windows(rows: np.ndarray, labels: np.ndarray, scenarios: np.ndarray,
                 spec: WindowSpec,
                 dense_labels: frozenset[int] = frozenset()) -> tuple[np.ndarray, ...]:
    """Slide a window over consecutive rows.

    A window is labelled by the most severe thing inside it (attack > natural >
    normal), not by its last row. A window that contains the first moment of an
    attack IS an attack window -- labelling by the final row would mark the
    onset window normal and make early detection look like a false positive,
    which is backwards.

    `dense_labels` are windowed at stride 1 instead of `spec.stride`. This
    exists because MSU/ORNL is built for *supervised* work: it is 74% attack
    and under 5% no-event, so the class this model actually trains on is the
    scarce one. At stride 10 that is ~30 seconds of normal operation in total,
    which is not enough to fit an autoencoder.

    What this does and does not buy: overlapping windows give the optimiser
    more gradient steps over the same underlying signal, but they are heavily
    correlated, so the *effective* sample size is far smaller than the window
    count. It is oversampling, not new data, and any claim about how much
    normal data the model saw must be stated in seconds of recording rather
    than in windows.
    """
    T, S = spec.length, spec.stride
    n = rows.shape[0]
    if n < T:
        return (np.empty((0, T, rows.shape[1]), np.float32),
                np.empty(0, np.int64), np.empty(0, np.int64),
                np.empty(0, np.int64))

    if dense_labels:
        cand = np.arange(0, n - T + 1)
        worst = np.array([labels[s:s + T].max() for s in cand])
        keep = np.isin(worst, list(dense_labels)) | (cand % S == 0)
        starts = cand[keep]
    else:
        starts = np.arange(0, n - T + 1, S)
    X = np.stack([rows[s:s + T] for s in starts]).astype(np.float32)

    y = np.empty(len(starts), np.int64)
    sc = np.empty(len(starts), np.int64)
    onset = np.full(len(starts), -1, np.int64)

    for i, s in enumerate(starts):
        win_lab = labels[s:s + T]
        worst = int(win_lab.max())
        y[i] = worst
        if worst == LABEL_NORMAL:
            sc[i] = int(scenarios[s:s + T][0])
        else:
            hits = np.flatnonzero(win_lab == worst)
            onset[i] = int(hits[0])
            sc[i] = int(scenarios[s:s + T][hits[0]])

    return X, y, sc, onset


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------

@dataclass
class Normaliser:
    """Per-feature standardisation with **persisted** statistics.

    REMAINING_WORK 3.2: "a detector that renormalises at inference time will
    drift". Fitting on each incoming window would rescale an attack back to
    looking ordinary -- the anomaly is precisely a change in scale, so
    normalising it away destroys the signal. Statistics are fitted once on
    training normal and saved with the weights.
    """

    mean: np.ndarray
    std: np.ndarray

    @classmethod
    def fit(cls, X: np.ndarray) -> "Normaliser":
        flat = X.reshape(-1, X.shape[-1])
        mean = flat.mean(axis=0)
        std = flat.std(axis=0)
        # Constant features (relay flags that never fire in the training slice)
        # would divide by zero. Leave them at zero variance rather than
        # amplifying float noise into a feature that looks informative.
        std = np.where(std < 1e-6, 1.0, std)
        return cls(mean.astype(np.float32), std.astype(np.float32))

    def __call__(self, X: np.ndarray) -> np.ndarray:
        return ((X - self.mean) / self.std).astype(np.float32)

    def save(self, path: Path) -> None:
        np.savez(path, mean=self.mean, std=self.std)

    @classmethod
    def load(cls, path: Path) -> "Normaliser":
        d = np.load(path)
        return cls(d["mean"], d["std"])


# ---------------------------------------------------------------------------
# MSU/ORNL loader
# ---------------------------------------------------------------------------

def _read_table(path: Path) -> tuple[list[str], list[list[float]], list[int]]:
    """Read one MSU/ORNL file, ARFF or CSV.

    The multiclass variant ships as ARFF despite being named `*.csv.arff` --
    Weka's format, with a `@attribute` block and a `@data` marker. The binary
    and three-class variants are plain CSV. Both appear here so the loader
    works whichever variant is downloaded.

    Non-numeric cells become 0.0 rather than dropping the row. This dataset is
    known to contain `Infinity` in some impedance columns, and ARFF uses `?`
    for missing. Dropping those rows would punch holes in the time series and
    silently break windowing, which assumes consecutive samples; substituting a
    neutral value keeps the sequence intact. Normalisation later maps 0.0 to
    the feature mean, so these cells carry no spurious signal.
    """
    names: list[str] = []
    rows: list[list[float]] = []
    scens: list[int] = []

    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        text = fh.read()

    lines = text.splitlines()
    is_arff = any(ln.lstrip().lower().startswith(("@relation", "@attribute"))
                  for ln in lines[:200])

    if is_arff:
        header: list[str] = []
        data_at = None
        for i, ln in enumerate(lines):
            low = ln.lstrip().lower()
            if low.startswith("@attribute"):
                parts = ln.split()
                if len(parts) >= 2:
                    header.append(parts[1].strip().strip("'\""))
            elif low.startswith("@data"):
                data_at = i + 1
                break
        if data_at is None:
            raise ValueError(f"{path.name}: ARFF with no @data section")
        body = lines[data_at:]
    else:
        import csv as _csv

        header = next(_csv.reader([lines[0]]))
        header = [h.strip() for h in header]
        body = lines[1:]

    marker_ix = len(header) - 1
    for j, h in enumerate(header):
        if h.strip().lower() == "marker":
            marker_ix = j
            break
    cols = [j for j in range(len(header)) if j != marker_ix]
    names = [header[j] for j in cols]

    for raw in body:
        raw = raw.strip()
        if not raw or raw.startswith("%"):
            continue
        rec = raw.split(",")
        if len(rec) <= marker_ix:
            continue
        try:
            scenario = int(float(rec[marker_ix].strip().strip("'\"")))
        except ValueError:
            continue
        vals = []
        for j in cols:
            tok = rec[j].strip() if j < len(rec) else ""
            try:
                v = float(tok)
                vals.append(v if np.isfinite(v) else 0.0)
            except ValueError:
                vals.append(0.0)
        if len(vals) != len(cols):
            continue
        rows.append(vals)
        scens.append(scenario)

    return names, rows, scens


def load_multiclass(data_dir: Path, spec: WindowSpec | None = None,
                    strict: bool = True,
                    dense_normal: bool = True) -> Dataset:
    """Load the MSU/ORNL multiclass files from `data_dir`.

    Expects the 15 files of the multiclass variant: 128 features plus a
    `marker` column holding the scenario id.

    `strict` asserts the documented structure (37 scenarios, 8 natural, 1
    no-event). A mismatch means the grouping table above is wrong for this copy
    of the data and every downstream number would be quietly corrupted, so it
    raises rather than warning.
    """
    spec = spec or WindowSpec(sample_hz=120.0)
    files = sorted(list(data_dir.glob("*.arff")) + list(data_dir.glob("*.csv")))
    if not files:
        raise FileNotFoundError(
            f"no .arff or .csv in {data_dir}. See server/LSTM/README.md."
        )

    all_rows, all_lab, all_sc = [], [], []
    feature_names: list[str] = []

    for fp in files:
        names, rows, scens = _read_table(fp)
        if not rows:
            continue
        if not feature_names:
            feature_names = names
        elif len(names) != len(feature_names):
            raise ValueError(
                f"{fp.name} has {len(names)} features but earlier files had "
                f"{len(feature_names)}; mixing dataset variants would align "
                f"different quantities under the same column index"
            )
        all_rows.append(np.asarray(rows, np.float32))
        all_lab.append(np.asarray([scenario_to_label(s) for s in scens], np.int64))
        all_sc.append(np.asarray(scens, np.int64))

    if not all_rows:
        raise ValueError(f"{len(files)} files in {data_dir} produced no rows")

    seen = set(np.concatenate(all_sc).tolist())
    n_nat = len(seen & set(NATURAL_SCENARIOS))
    n_none = len(seen & set(NO_EVENT_SCENARIOS))
    msg = (f"scenarios found: {len(seen)} (expected 37); "
           f"natural {n_nat}/8; no-event {n_none}/1")
    if strict and (len(seen) != 37 or n_nat != 8 or n_none != 1):
        raise ValueError(
            msg + ". The grouping table in data.py does not match this copy of "
            "the dataset. Check it against PowerSystem_Dataset_README.pdf "
            "before trusting any result -- mislabelled natural events would "
            "make the detector look better exactly where it should be hardest."
        )
    if not strict:
        warnings.warn(msg)

    # Window each file separately: a window must never straddle two
    # recordings. No-event rows are windowed densely by default -- they are
    # the only class this model trains on and the dataset has very few.
    dense = frozenset({LABEL_NORMAL}) if dense_normal else frozenset()
    Xs, ys, scs_, ons = [], [], [], []
    for r, l, s in zip(all_rows, all_lab, all_sc):
        X, y, sc, on = make_windows(r, l, s, spec, dense_labels=dense)
        if len(X):
            Xs.append(X); ys.append(y); scs_.append(sc); ons.append(on)

    if not Xs:
        raise ValueError(
            f"no window of {spec.length} rows fits any file; longest file has "
            f"{max(len(r) for r in all_rows)} rows"
        )

    return Dataset(np.concatenate(Xs), np.concatenate(ys),
                   np.concatenate(scs_), np.concatenate(ons),
                   spec, feature_names)


# ---------------------------------------------------------------------------
# Synthetic source — so every other module is testable without the download
# ---------------------------------------------------------------------------

def synthetic(n_normal: int = 400, n_natural: int = 60, n_attack: int = 120,
              n_features: int = 12, spec: WindowSpec | None = None,
              seed: int = 0) -> Dataset:
    """A stand-in with the same shape and the same *hard part*.

    Not a substitute for the real evaluation, and nothing reported from it goes
    in the paper. Its job is to keep the rest of the pipeline testable and to
    exercise the case that actually matters: natural disturbances are large,
    obvious departures from normal that are **not** attacks. If a detector only
    separates "quiet" from "loud" it will score beautifully here on attacks and
    fail completely on naturals -- which is the failure this whole design is
    arranged to avoid.

    Attacks are therefore *structurally* different (a sustained offset on a few
    correlated channels) rather than merely larger.
    """
    spec = spec or WindowSpec(length=60, stride=60, sample_hz=1.0)
    rng = np.random.default_rng(seed)
    T, F = spec.length, n_features

    def base(n):
        t = np.linspace(0, 4 * np.pi, T)[None, :, None]
        phase = rng.uniform(0, 2 * np.pi, size=(n, 1, F))
        sig = np.sin(t + phase) + 0.05 * rng.standard_normal((n, T, F))
        return sig.astype(np.float32)

    Xn = base(n_normal)

    # Onsets must leave room for the event to develop, at any window length.
    # The literal `5, T - 20` this started as crashed for T <= 25.
    onset_lo = max(1, T // 8)
    onset_hi = max(onset_lo + 1, T - max(3, T // 4))

    # Natural: a big transient on ALL channels, then recovery. Loud, benign.
    Xnat = base(n_natural)
    nat_onsets = []
    for i in range(n_natural):
        s = int(rng.integers(onset_lo, onset_hi))
        nat_onsets.append(s)
        decay = np.exp(-np.arange(T - s) / 6.0)[:, None]
        Xnat[i, s:, :] += (4.0 * decay * rng.choice([-1.0, 1.0])).astype(np.float32)

    # Attack: a quiet, sustained offset on a few correlated channels, plus a
    # frozen channel (replayed/held sensor). Smaller in magnitude than the
    # natural transient, and that is the point.
    Xatk = base(n_attack)
    atk_only = []
    atk_onsets = []
    for i in range(n_attack):
        s = int(rng.integers(onset_lo, onset_hi))
        atk_onsets.append(s)
        k = int(rng.integers(2, max(3, F // 3)))
        feats = rng.choice(F, size=k, replace=False)
        Xatk[i, s:, feats] += 0.9
        frozen = int(rng.choice(feats))
        Xatk[i, s:, frozen] = Xatk[i, s, frozen]
        atk_only.append(sorted(feats.tolist()))

    # Aligned with X: normal and natural windows have no injected fault, so
    # they carry an empty list rather than being absent.
    atk_feat = ([[]] * n_normal) + ([[]] * n_natural) + atk_only

    X = np.concatenate([Xn, Xnat, Xatk]).astype(np.float32)
    y = np.concatenate([
        np.full(n_normal, LABEL_NORMAL, np.int64),
        np.full(n_natural, LABEL_NATURAL, np.int64),
        np.full(n_attack, LABEL_ATTACK, np.int64),
    ])
    sc = np.concatenate([
        np.full(n_normal, 41, np.int64),
        rng.choice(sorted(NATURAL_SCENARIOS), size=n_natural),
        rng.integers(15, 41, size=n_attack),
    ])
    # The ACTUAL injection points, not fresh draws. Detection delay is measured
    # from this index, so an independently sampled onset would scatter the
    # measurement around the truth and still produce a plausible-looking
    # distribution -- a wrong number with no symptom.
    onset = np.concatenate([
        np.full(n_normal, -1, np.int64),
        np.asarray(nat_onsets, np.int64),
        np.asarray(atk_onsets, np.int64),
    ])

    return Dataset(X, y, sc, onset, spec,
                   [f"f{i}" for i in range(F)], atk_feat)


def split_normal(ds: Dataset, train_frac: float = 0.6, calib_frac: float = 0.2,
                 seed: int = 0,
                 benign: tuple[int, ...] = (LABEL_NORMAL,)) -> tuple[Dataset, Dataset, Dataset]:
    """Split into (train-benign, calibrate-benign, evaluate-everything).

    Training and calibration must not share windows: calibrating on data the
    autoencoder was fitted to would report reconstruction errors lower than
    anything production will ever see, and every threshold derived from it
    would be too tight.

    `benign` is which labels count as "not an attack" for training.

    * `(LABEL_NORMAL,)` -- the strict reading, train on a calm grid only.
    * `(LABEL_NORMAL, LABEL_NATURAL)` -- train on everything benign, faults
      included.

    The second is the one that matches deployment, and the distinction turns
    out to matter enormously. "Normal" does not mean *nothing happening*; it
    means *not under attack*. A substation throws faults, line maintenance and
    load swings constantly, and a rig collecting its own training data will
    record all of them without ever labelling one. Training only on the calm
    grid teaches the model that any disturbance is remarkable -- which is why
    the strict split flags 99.9% of natural disturbances as attacks.

    Held-out benign windows still land in the evaluation split, so natural
    disturbances are never scored on data the model trained on.
    """
    rng = np.random.default_rng(seed)
    normal_ix = np.flatnonzero(np.isin(ds.y, list(benign)))
    rng.shuffle(normal_ix)

    n_tr = int(len(normal_ix) * train_frac)
    n_ca = int(len(normal_ix) * calib_frac)
    tr, ca, rest = (normal_ix[:n_tr], normal_ix[n_tr:n_tr + n_ca],
                    normal_ix[n_tr + n_ca:])

    ev = np.concatenate([np.flatnonzero(~np.isin(ds.y, list(benign))), rest])

    def mask(ix):
        m = np.zeros(len(ds), bool)
        m[ix] = True
        return m

    return ds.subset(mask(tr)), ds.subset(mask(ca)), ds.subset(mask(ev))
