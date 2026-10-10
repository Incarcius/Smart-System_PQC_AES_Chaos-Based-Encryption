"""
aggregator.py — the 1 s telemetry window, and quarantine isolation.

Collects per-channel readings from every leaf over one aggregation window and
emits a single batch for the uplink.

Quarantine
----------
Confirmed semantics: **isolate and continue as untrusted; dump on a confirmed
major anomaly.** So a quarantined channel is a *trust* state, not a crypto
state — the owning ESP32 keeps a valid session key and keeps being ingested.

Concretely, a quarantined channel:

  - is excluded from the normal aggregate the server treats as trustworthy
  - is still collected, into a separate buffer tagged untrusted
  - is still counted, so its silence would itself be visible
  - is dropped wholesale once the anomaly is confirmed

Keeping it flowing is what makes triage possible: an operator needs to see
what the suspect channel was doing, and a channel that simply vanished is
indistinguishable from a dead sensor.

The batch payload is JSON. It is inside AES-GCM and then under the ACCM mask,
so its verbosity costs bandwidth but leaks nothing, and a self-describing
format is worth a great deal when the LSTM's feature layout is still moving.
Swap it for a packed binary encoding once the schema settles.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Sample:
    endpoint_id: int
    channel_id: int
    value: float
    quality: int
    timestamp_ms: int


@dataclass
class Batch:
    """One aggregation window, ready for the uplink."""

    window_start_ms: int
    window_end_ms: int
    trusted: list[Sample] = field(default_factory=list)
    untrusted: list[Sample] = field(default_factory=list)
    silent_channels: list[int] = field(default_factory=list)

    @property
    def sample_count(self) -> int:
        return len(self.trusted) + len(self.untrusted)

    def encode(self) -> bytes:
        """Serialise for the uplink payload."""
        return json.dumps(
            {
                "t0": self.window_start_ms,
                "t1": self.window_end_ms,
                "trusted": [
                    [s.endpoint_id, s.channel_id, round(s.value, 6), s.quality, s.timestamp_ms]
                    for s in self.trusted
                ],
                "untrusted": [
                    [s.endpoint_id, s.channel_id, round(s.value, 6), s.quality, s.timestamp_ms]
                    for s in self.untrusted
                ],
                "silent": self.silent_channels,
            },
            separators=(",", ":"),
        ).encode()

    @staticmethod
    def decode(raw: bytes) -> "Batch":
        d = json.loads(raw)
        def mk(rows):
            return [Sample(e, c, v, q, t) for e, c, v, q, t in rows]
        return Batch(
            window_start_ms=d["t0"],
            window_end_ms=d["t1"],
            trusted=mk(d["trusted"]),
            untrusted=mk(d["untrusted"]),
            silent_channels=list(d["silent"]),
        )


class Aggregator:
    """Accumulates samples; `drain()` closes the window and returns a Batch."""

    def __init__(self, expected_channels: set[int] | None = None) -> None:
        self._samples: list[Sample] = []
        self._window_start_ms: int | None = None
        self.expected_channels = expected_channels or set()

        # Rolling per-channel counts, for the policy's rate-deviation feature.
        self.channel_counts: dict[int, int] = defaultdict(int)

    def add(self, sample: Sample) -> None:
        if self._window_start_ms is None:
            self._window_start_ms = sample.timestamp_ms
        self._samples.append(sample)
        self.channel_counts[sample.channel_id] += 1

    def add_frame(
        self, endpoint_id: int, timestamp_ms: int, readings, channel_ids=None
    ) -> None:
        """Ingest one opened leaf frame.

        `readings` are in channel order as the leaf sent them; `channel_ids`
        maps position to the global channel id. Without it, position is used
        directly — correct for the single-endpoint prototype, and the hook that
        makes multi-endpoint deployments work without touching this class.
        """
        for i, r in enumerate(readings):
            cid = channel_ids[i] if channel_ids else i
            self.add(Sample(endpoint_id, cid, r.value, r.quality, timestamp_ms))

    def drain(self, now_ms: int, quarantined_mask: int = 0) -> Batch:
        """Close the window. Splits trusted from quarantined and resets."""
        start = self._window_start_ms if self._window_start_ms is not None else now_ms
        batch = Batch(window_start_ms=start, window_end_ms=now_ms)

        seen: set[int] = set()
        for s in self._samples:
            seen.add(s.channel_id)
            if quarantined_mask & (1 << s.channel_id):
                batch.untrusted.append(s)
            else:
                batch.trusted.append(s)

        # A channel that reported nothing this window. Reported explicitly
        # rather than inferred from absence, because the server cannot tell a
        # silent sensor from a dropped batch.
        batch.silent_channels = sorted(self.expected_channels - seen)

        self._samples = []
        self._window_start_ms = None
        return batch

    @property
    def pending(self) -> int:
        return len(self._samples)


__all__ = ["Aggregator", "Batch", "Sample"]
