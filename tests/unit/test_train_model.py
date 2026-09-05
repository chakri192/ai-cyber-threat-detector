"""inference/train_model.py had 0% coverage despite carrying the
.sha256-sidecar fix: without it, the next DeepLearningEngine startup's
integrity check finds a stale/missing hash and crash-loops the fleet.
save_traced_model() was pulled out of the training loop specifically so
this could be tested without running a real 100k-sample training loop.
"""
import hashlib

import torch
import torch.nn as nn

from inference.train_model import DGA_CNN, generate_hard_dataset, save_traced_model


def test_save_traced_model_writes_matching_sha256(tmp_path):
    model = DGA_CNN()
    model.eval()
    traced = torch.jit.trace(model, torch.zeros((1, 35), dtype=torch.long))
    save_path = str(tmp_path / "cnn_dga.pt")

    returned_hash = save_traced_model(traced, save_path)

    with open(save_path, "rb") as f:
        expected_hash = hashlib.sha256(f.read()).hexdigest()
    with open(save_path + ".sha256") as f:
        written_hash = f.read().strip()

    assert returned_hash == expected_hash
    assert written_hash == expected_hash


def test_save_traced_model_overwrites_stale_sha256(tmp_path):
    model = DGA_CNN()
    model.eval()
    traced = torch.jit.trace(model, torch.zeros((1, 35), dtype=torch.long))
    save_path = str(tmp_path / "cnn_dga.pt")

    with open(save_path + ".sha256", "w") as f:
        f.write("stale-hash-from-a-previous-model\n")

    save_traced_model(traced, save_path)

    with open(save_path, "rb") as f:
        expected_hash = hashlib.sha256(f.read()).hexdigest()
    with open(save_path + ".sha256") as f:
        assert f.read().strip() == expected_hash


def test_generate_hard_dataset_shapes_and_labels():
    X, y = generate_hard_dataset(num_samples=20)
    assert X.shape == (20, 35)
    assert y.shape == (20, 1)
    assert X.dtype == torch.long
    # Half malicious (label 1.0), half benign (label 0.0), by construction.
    assert set(y.unique().tolist()) <= {0.0, 1.0}
    assert y.sum().item() == 10.0


def test_dga_cnn_forward_produces_probability_in_unit_range():
    model = DGA_CNN()
    model.eval()
    with torch.no_grad():
        out = model(torch.zeros((2, 35), dtype=torch.long))
    assert out.shape == (2, 1)
    assert torch.all((out >= 0.0) & (out <= 1.0))
