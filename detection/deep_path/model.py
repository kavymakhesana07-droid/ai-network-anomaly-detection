"""LSTM Autoencoder model for deep-path reconstruction-based detection.

Kept apart from models.py on purpose: models.py is dependency-free so the unit
test suite runs without the heavy ML stack. This module imports torch and
PyTorch Lightning and is only loaded by the runtime service or trainer.
"""

from __future__ import annotations

from typing import Any

import lightning as pl
import torch
from torch import nn
from torch.utils.data import Dataset

from .models import DeepPathConfig, FlowSequence


class LstmAutoencoder(pl.LightningModule):  # type: ignore[misc]
    """Sequence-to-sequence LSTM autoencoder.

    Encodes a [B, T, F] window into a latent vector, then decodes the latent
    back into a full-length reconstruction. Flows that the model cannot
    reconstruct well (high MSE) are the anomalies.
    """

    def __init__(self, config: DeepPathConfig) -> None:
        super().__init__()
        self.config = config
        self.learning_rate = config.learning_rate

        dropout = config.dropout if config.num_layers > 1 else 0.0
        self.encoder = nn.LSTM(
            input_size=config.input_dim,
            hidden_size=config.hidden_dim,
            num_layers=config.num_layers,
            batch_first=True,
            dropout=dropout,
        )
        self.latent = nn.Linear(config.hidden_dim, config.latent_dim)
        self.decode_init = nn.Linear(config.latent_dim, config.hidden_dim)
        self.decoder = nn.LSTM(
            input_size=config.hidden_dim,
            hidden_size=config.hidden_dim,
            num_layers=config.num_layers,
            batch_first=True,
            dropout=dropout,
        )
        self.output = nn.Linear(config.hidden_dim, config.input_dim)

    def encode(self, x: torch.Tensor) -> torch.Tensor:
        """Map a [B, T, F] window to a [B, latent_dim] code."""
        _, (h_n, _) = self.encoder(x)  # h_n: (num_layers, B, hidden_dim)
        return self.latent(h_n[-1])

    def decode(self, z: torch.Tensor, seq_len: int) -> torch.Tensor:
        """Rebuild a [B, T, F] window from a [B, latent_dim] code."""
        batch = z.size(0)
        h0 = (
            self
            .decode_init(z)
            .unsqueeze(0)
            .expand(self.config.num_layers, batch, self.config.hidden_dim)
            .contiguous()
        )
        c0 = torch.zeros_like(h0)
        seed = h0[0].unsqueeze(1).expand(batch, seq_len, self.config.hidden_dim).contiguous()
        out, _ = self.decoder(seed, (h0, c0))
        return self.output(out)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.decode(self.encode(x), x.size(1))

    def _mse(self, batch: torch.Tensor) -> Any:
        return nn.functional.mse_loss(self(batch), batch)

    def training_step(self, batch: torch.Tensor, _batch_idx: int) -> Any:
        loss = self._mse(batch)
        self.log("train_loss", loss, on_step=True, on_epoch=True, prog_bar=True)
        return loss

    def validation_step(self, batch: torch.Tensor, _batch_idx: int) -> Any:
        loss = self._mse(batch)
        self.log("val_loss", loss, on_step=False, on_epoch=True, prog_bar=True)
        return loss

    def test_step(self, batch: torch.Tensor, _batch_idx: int) -> Any:
        loss = self._mse(batch)
        self.log("test_loss", loss, on_step=False, on_epoch=True)
        return loss

    def configure_optimizers(self) -> Any:
        return torch.optim.Adam(self.parameters(), lr=self.learning_rate)


class LstmSeqDataset(Dataset[FlowSequence]):  # type: ignore[misc]
    """Wraps FlowSequence objects for the PyTorch DataLoader."""

    def __init__(self, sequences: list[FlowSequence]) -> None:
        self.sequences = sequences

    def __len__(self) -> int:
        return len(self.sequences)

    def __getitem__(self, index: int) -> FlowSequence:
        return self.sequences[index]


def seq_collate(batch: list[FlowSequence]) -> torch.Tensor:
    """Collate variable-length batch into a [B, T, F] tensor.

    Sequences are built with a fixed window length, so no padding is needed -
    but the row count stays explicit for clarity.
    """
    return torch.tensor([seq.sequences for seq in batch], dtype=torch.float32)


def build_model(config: DeepPathConfig) -> LstmAutoencoder:
    return LstmAutoencoder(config)
