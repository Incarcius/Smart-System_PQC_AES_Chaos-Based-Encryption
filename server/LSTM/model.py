"""model.py — the LSTM autoencoder.

Why an autoencoder and not a classifier
---------------------------------------
A supervised classifier needs labelled attacks. A healthy rig produces none,
and never will — you cannot wait for your own substation to be attacked in
order to start detecting attacks. The autoencoder trains on **normal only**,
which is the data that actually exists, and reports how badly it fails to
reconstruct what it is shown.

It also gives node attribution for free. Reconstruction error is per-feature by
construction, so "which channel is wrong" falls out of the same forward pass
that produces the score. A classifier would need a separate explanation
mechanism to drive `tg_control_t.node_mask`, and quarantine that cannot name a
node is not actionable.

Architecture (REMAINING_WORK 3.2)
---------------------------------
    (T, F) -> LSTM(64) -> LSTM(32) -> latent Dense(16)
           -> repeat T -> LSTM(32) -> LSTM(64) -> Linear(F) -> (T, F)

The bottleneck is the whole mechanism: 16 numbers cannot memorise a 60-step
window, so the network is forced to learn the *regularities* of normal
operation. Anything not expressible in those regularities reconstructs badly,
and that is the signal. Widen the latent far enough and the autoencoder learns
the identity function, reconstructs attacks perfectly, and detects nothing —
a failure that shows up as suspiciously low training loss and no separation at
evaluation, not as an error.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path

import torch
import torch.nn as nn


@dataclass
class ModelConfig:
    n_features: int = 128
    window: int = 60
    hidden1: int = 64
    hidden2: int = 32
    latent: int = 16
    dropout: float = 0.0


class LSTMAutoencoder(nn.Module):
    def __init__(self, cfg: ModelConfig) -> None:
        super().__init__()
        self.cfg = cfg

        self.enc1 = nn.LSTM(cfg.n_features, cfg.hidden1, batch_first=True)
        self.enc2 = nn.LSTM(cfg.hidden1, cfg.hidden2, batch_first=True)
        self.to_latent = nn.Linear(cfg.hidden2, cfg.latent)

        self.dec1 = nn.LSTM(cfg.latent, cfg.hidden2, batch_first=True)
        self.dec2 = nn.LSTM(cfg.hidden2, cfg.hidden1, batch_first=True)
        self.out = nn.Linear(cfg.hidden1, cfg.n_features)
        self.drop = nn.Dropout(cfg.dropout) if cfg.dropout > 0 else nn.Identity()

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        h, _ = self.enc1(x)
        h, _ = self.enc2(h)
        # Last timestep only: the encoder's final hidden state must summarise
        # the whole window, which is what forces the bottleneck to be about
        # temporal structure rather than per-step compression.
        return self.to_latent(h[:, -1, :])

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.encode(x)
        z = self.drop(z)
        rep = z.unsqueeze(1).expand(-1, x.shape[1], -1)
        h, _ = self.dec1(rep)
        h, _ = self.dec2(h)
        return self.out(h)

    # -- error surfaces -----------------------------------------------------
    #
    # Three reductions of the same squared error, and keeping them distinct
    # matters: the score needs one number per window, attribution needs one per
    # feature, and detection delay needs one per timestep.

    @staticmethod
    def _sq(x: torch.Tensor, recon: torch.Tensor) -> torch.Tensor:
        return (x - recon) ** 2

    def error_per_window(self, x: torch.Tensor) -> torch.Tensor:
        return self._sq(x, self(x)).mean(dim=(1, 2))

    def error_per_feature(self, x: torch.Tensor) -> torch.Tensor:
        """(B, F) — drives `attribute()`."""
        return self._sq(x, self(x)).mean(dim=1)

    def error_per_step(self, x: torch.Tensor) -> torch.Tensor:
        """(B, T) — drives detection delay.

        Delay is measured from the row where the event starts to the row where
        the error crosses threshold, so it needs the error resolved in time.
        Averaging over the window first would make delay unmeasurable.
        """
        return self._sq(x, self(x)).mean(dim=2)

    # -- persistence --------------------------------------------------------

    def save(self, path: Path) -> None:
        torch.save({"cfg": asdict(self.cfg), "state": self.state_dict()}, path)

    @classmethod
    def load(cls, path: Path, map_location="cpu") -> "LSTMAutoencoder":
        blob = torch.load(path, map_location=map_location, weights_only=False)
        m = cls(ModelConfig(**blob["cfg"]))
        m.load_state_dict(blob["state"])
        m.eval()
        return m


def count_parameters(m: nn.Module) -> int:
    return sum(p.numel() for p in m.parameters() if p.requires_grad)
