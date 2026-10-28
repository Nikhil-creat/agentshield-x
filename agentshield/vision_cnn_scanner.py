"""Multi-modal image scanner: hidden text, steganography, QR injection, adversarial noise.

Pipeline (every stage fails closed; any exception => BLOCK):
  0. Hard limits: byte cap, decompression-bomb cap, format allow-list, animated => frame 0 only.
  1. Container-level: trailing bytes after the image end (polyglots), metadata/EXIF/text chunks
     scanned for instructions.
  2. OCR (Tesseract CLI): visible *and* contrast-amplified passes. Instruction hits that only
     appear after amplification are reported as hidden text.
  3. Steganography: extracts the LSB stream under several channel/bit orders and checks for
     printable text, length-prefixed text or file magics (low false-positive by construction),
     plus an LSB-plane decorrelation heuristic for rendered/flat imagery.
  4. QR: OpenCV/pyzbar decoder when installed; otherwise a finder-pattern (1:1:3:1:1) detector
     that at least proves a QR code is present. Decoded payloads are scanned as untrusted text.
  5. Adversarial perturbation: noise-on-flat-image heuristic + the ONNX *visual guard* CNN
     (MobileNetV3-small head; see ``build_visual_guard_model``). No weights ship in this repo -
     train on your own adversarial corpus (``scripts/train_visual_guard.py``).
  6. Purification: median filter + 5-bit posterize + metadata strip + PNG re-encode. This destroys
     LSB payloads, faint text and much low-amplitude adversarial noise; only the purified image
     should ever be forwarded to a VLM.

Heuristics here detect *common* attack constructions, not all of them. Treat the scanner as one
layer; the CNN is the extension point for broader coverage.
"""

from __future__ import annotations

import asyncio
import io
import math
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

import numpy as np
from PIL import Image, ImageFilter, ImageOps

from .config import ShieldSettings
from .shield_types import Finding, ThreatCategory as C, TrustLevel, Verdict, noisy_or
from .signatures import scan_instructions
from .text_normalizer import normalize

ALLOWED_FORMATS = {"PNG", "JPEG", "WEBP", "BMP", "GIF"}
_MAGICS = (b"PK\x03\x04", b"%PDF", b"\x89PNG", b"\x7fELF", b"Rar!", b"GIF8", b"\x1f\x8b\x08", b"MZ\x90\x00", b"SQLite format")


# --------------------------------------------------------------------------------------
# OCR + QR backends
# --------------------------------------------------------------------------------------
class OcrEngine(Protocol):
    available: bool

    def read(self, img: Image.Image, timeout_s: float = 12.0) -> str: ...


class TesseractCliOcr:
    """OCR through the ``tesseract`` binary (no Python wrapper required)."""

    def __init__(self, lang: str = "eng") -> None:
        self.lang = lang
        self.available = shutil.which("tesseract") is not None

    def read(self, img: Image.Image, timeout_s: float = 12.0) -> str:
        if not self.available:
            return ""
        buf = io.BytesIO()
        img.convert("L").save(buf, "PNG")
        try:
            p = subprocess.run(["tesseract", "stdin", "stdout", "--psm", "6", "-l", self.lang], input=buf.getvalue(),
                               capture_output=True, timeout=timeout_s, check=False)
            return p.stdout.decode("utf-8", "ignore")
        except (subprocess.TimeoutExpired, OSError):
            return ""


def _decode_qr(img: Image.Image) -> list[str] | None:
    """Return decoded payloads, or ``None`` when no decoder is installed."""
    try:
        import cv2  # type: ignore[import-not-found]

        arr = np.asarray(img.convert("RGB"))
        det = cv2.QRCodeDetector()
        ok, decoded, _, _ = det.detectAndDecodeMulti(arr)
        if ok:
            return [d for d in decoded if d]
        d, _, _ = det.detectAndDecode(arr)
        return [d] if d else []
    except ImportError:
        pass
    try:
        from pyzbar.pyzbar import decode  # type: ignore[import-not-found]

        return [r.data.decode("utf-8", "ignore") for r in decode(img)]
    except ImportError:
        return None


# --------------------------------------------------------------------------------------
# Learned guard (ONNX Runtime)
# --------------------------------------------------------------------------------------
class OnnxVisualGuard:
    """Runs the exported MobileNet/ResNet visual-attack classifier on CPU via ONNX Runtime."""

    LABELS = ("clean", "adversarial", "visual_injection")
    _MEAN = np.array([0.485, 0.456, 0.406], dtype=np.float32)
    _STD = np.array([0.229, 0.224, 0.225], dtype=np.float32)

    def __init__(self, path: str) -> None:
        self.available = False
        self._sess: Any = None
        if path and os.path.isfile(path):
            try:
                import onnxruntime as ort

                so = ort.SessionOptions()
                so.intra_op_num_threads = 1
                so.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
                self._sess = ort.InferenceSession(path, so, providers=["CPUExecutionProvider"])
                self._in = self._sess.get_inputs()[0].name
                self.available = True
            except Exception:  # noqa: BLE001 - corrupt model => unavailable (caller decides to fail closed)
                self.available = False

    def predict(self, img: Image.Image) -> dict[str, float]:
        a = np.asarray(img.convert("RGB").resize((224, 224), Image.BILINEAR), dtype=np.float32) / 255.0
        a = ((a - self._MEAN) / self._STD).transpose(2, 0, 1)[None].astype(np.float32)
        logits = self._sess.run(None, {self._in: a})[0][0].astype(np.float64)
        e = np.exp(logits - logits.max())
        p = e / e.sum()
        return {k: float(v) for k, v in zip(self.LABELS, p)}


def build_visual_guard_model(pretrained: bool = False):  # pragma: no cover - needs torch/torchvision
    """MobileNetV3-small with a 3-way head (clean / adversarial / visual_injection)."""
    import torch.nn as nn
    from torchvision.models import mobilenet_v3_small

    m = mobilenet_v3_small(weights="DEFAULT" if pretrained else None)
    m.classifier[-1] = nn.Linear(m.classifier[-1].in_features, len(OnnxVisualGuard.LABELS))
    return m


def export_onnx(model, path: str) -> None:  # pragma: no cover - needs torch
    import torch

    model.eval()
    torch.onnx.export(model, torch.zeros(1, 3, 224, 224), path, input_names=["input"], output_names=["logits"],
                      dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}}, opset_version=17)


# --------------------------------------------------------------------------------------
# Pixel analytics
# --------------------------------------------------------------------------------------
def lsb_stream(arr: np.ndarray, channels: Sequence[int], nbytes: int = 4096, bitorder: str = "big") -> bytes:
    bits = (arr[..., list(channels)].reshape(-1)[: nbytes * 8] & 1).astype(np.uint8)
    return np.packbits(bits, bitorder=bitorder).tobytes()


def _printable_prefix(b: bytes) -> int:
    n = 0
    for c in b:
        if 32 <= c <= 126 or c in (9, 10, 13):
            n += 1
        else:
            break
    return n


def stego_payloads(arr: np.ndarray) -> list[tuple[str, str]]:
    """Return [(variant, text-or-'magic:<hex>')] for LSB streams that look like deliberate payloads."""
    variants: list[tuple[str, Sequence[int]]] = [("rgb", (0, 1, 2)), ("r", (0,)), ("g", (1,)), ("b", (2,))]
    if arr.shape[-1] == 4 and arr[..., 3].min() != arr[..., 3].max():
        variants.append(("rgba", (0, 1, 2, 3)))
        variants.append(("a", (3,)))
    hits: list[tuple[str, str]] = []
    for name, ch in variants:
        for order in ("big", "little"):
            s = lsb_stream(arr, ch, bitorder=order)
            tag = f"{name}/{order}"
            n = _printable_prefix(s)
            if n >= 12:
                hits.append((tag, s[:n].decode("ascii", "ignore")))
                continue
            L = int.from_bytes(s[:4], "big")
            if 8 <= L <= 2048 and _printable_prefix(s[4 : 4 + L]) == L:
                hits.append((tag + "/len", s[4 : 4 + L].decode("ascii", "ignore")))
                continue
            for m in _MAGICS:
                if s.startswith(m):
                    hits.append((tag, "magic:" + m.hex()))
    return hits


def lsb_decorrelation(arr: np.ndarray) -> tuple[float, float, float]:
    """(mean of LSB plane, horizontal agreement of LSB plane, agreement of bit-1 plane)."""
    ch = arr[..., 0]
    p0, p1 = ch & 1, (ch >> 1) & 1
    ag = lambda p: float(np.mean(p[:, :-1] == p[:, 1:]))  # noqa: E731
    return float(p0.mean()), ag(p0), ag(p1)


def noise_sigma(gray: np.ndarray) -> float:
    """Immerkaer fast noise-variance estimator (std-dev, in grey levels)."""
    g = gray.astype(np.float32)
    if g.shape[0] < 3 or g.shape[1] < 3:
        return 0.0
    c = (g[:-2, :-2] - 2 * g[:-2, 1:-1] + g[:-2, 2:] - 2 * g[1:-1, :-2] + 4 * g[1:-1, 1:-1] - 2 * g[1:-1, 2:]
         + g[2:, :-2] - 2 * g[2:, 1:-1] + g[2:, 2:])
    return float(math.sqrt(math.pi / 2) / 6.0 * np.mean(np.abs(c)))


def faint_structure(gray: np.ndarray) -> tuple[float, float, int]:
    """(mode_fraction, isolated-faint-pixel ratio, background level).

    Flat, document-like images with a dominant background value but *isolated* pixels that
    deviate from it by only a few levels (not adjacent to real ink) indicate low-contrast text.
    """
    hist = np.bincount(gray.ravel(), minlength=256)
    bg = int(hist.argmax())
    mode_frac = float(hist[bg] / gray.size)
    if mode_frac < 0.35:
        return mode_frac, 0.0, bg
    diff = np.abs(gray.astype(np.int16) - bg)
    strong = (diff > 24).astype(np.uint8) * 255
    near = np.asarray(Image.fromarray(strong).filter(ImageFilter.MaxFilter(11))) > 0
    faint = (diff >= 2) & (diff <= 24) & ~near
    h, w = faint.shape
    bh, bw = h // 16 * 16, w // 16 * 16
    if bh == 0 or bw == 0:
        return mode_frac, 0.0, bg
    blocks = faint[:bh, :bw].reshape(bh // 16, 16, bw // 16, 16).mean(axis=(1, 3))
    hot = int((blocks >= 0.06).sum())
    ratio = float(faint.sum() / faint.size)
    return mode_frac, (ratio if hot >= 3 else 0.0), bg


def amplify_faint(gray: np.ndarray, bg: int, gain: float = 30.0) -> Image.Image:
    """Map |value - bg| to ink darkness so faint text of either polarity becomes legible to OCR."""
    d = np.abs(gray.astype(np.float32) - bg)
    return Image.fromarray(np.clip(255.0 - d * gain, 0, 255).astype(np.uint8))


def _otsu(gray: np.ndarray) -> int:
    hist = np.bincount(gray.ravel(), minlength=256).astype(np.float64)
    total, sum_all = hist.sum(), (np.arange(256) * hist).sum()
    wb = sb = 0.0
    best, thr = -1.0, 127
    for t in range(256):
        wb += hist[t]
        if wb == 0:
            continue
        wf = total - wb
        if wf == 0:
            break
        sb += t * hist[t]
        var = wb * wf * (sb / wb - (sum_all - sb) / wf) ** 2
        if var > best:
            best, thr = var, t
    return thr


def find_qr_finder_patterns(gray: np.ndarray, max_rows: int = 600) -> int:
    """Count clusters matching the QR 1:1:3:1:1 finder signature (>=3 => a QR code is present)."""
    img = Image.fromarray(gray)
    if max(img.size) > 1200:
        s = 1200 / max(img.size)
        img = img.resize((max(1, int(img.width * s)), max(1, int(img.height * s))), Image.BILINEAR)
    g = np.asarray(img)
    bw = g <= _otsu(g)
    h, w = bw.shape
    step = max(1, h // max_rows)
    hits: list[tuple[float, int, float]] = []
    for y in range(0, h, step):
        row = bw[y]
        change = np.flatnonzero(np.diff(row.astype(np.int8))) + 1
        starts = np.concatenate(([0], change))
        lens = np.diff(np.concatenate((starts, [w])))
        vals = row[starts]
        for i in range(len(lens) - 4):
            if not vals[i]:
                continue
            r = lens[i : i + 5]
            tot = int(r.sum())
            if tot < 7:
                continue
            u = tot / 7.0
            if u < 2.0:  # sub-2px modules are undecodable and indistinguishable from noise
                continue
            if all(abs(r[j] - u) < 0.6 * u for j in (0, 1, 3, 4)) and abs(r[2] - 3 * u) < 1.2 * u:
                hits.append((starts[i] + tot / 2.0, y, u))
    clusters: list[dict[str, float]] = []
    for cx, y, u in sorted(hits, key=lambda t: t[1]):
        for c in clusters:
            if abs(cx - c["cx"]) < 2 * c["u"] and y - c["y1"] <= 2 * step + 2:
                c["y1"], c["n"] = y, c["n"] + 1
                break
        else:
            clusters.append({"cx": cx, "u": u, "y0": y, "y1": y, "n": 1})
    def vertical_ok(c: dict[str, float]) -> bool:
        x, ym = int(c["cx"]), int((c["y0"] + c["y1"]) / 2)
        if not 0 <= x < w:
            return False
        col = bw[:, x]
        ch = np.flatnonzero(np.diff(col.astype(np.int8))) + 1
        st = np.concatenate(([0], ch))
        ln = np.diff(np.concatenate((st, [h])))
        for i in range(len(ln) - 4):
            if st[i] <= ym < st[i + 4] + ln[i + 4] and col[st[i]]:
                r = ln[i : i + 5]
                u = r.sum() / 7.0
                if u > 0 and all(abs(r[j] - u) < 0.6 * u for j in (0, 1, 3, 4)) and abs(r[2] - 3 * u) < 1.2 * u:
                    return True
        return False

    good = [c for c in clusters if c["n"] >= 3 and vertical_ok(c) and (c["y1"] - c["y0"]) >= 2 * c["u"]]
    # A real QR has three finders in an L: same size, two share a row band, two share a column.
    for a in good:
        for b in good:
            for c in good:
                if a is b or a is c or b is c:
                    continue
                us = (a["u"], b["u"], c["u"])
                if max(us) > 1.35 * min(us):
                    continue
                u = sum(us) / 3
                if abs(a["y0"] - b["y0"]) < 2 * u and abs(a["cx"] - c["cx"]) < 2 * u and b["cx"] - a["cx"] > 7 * u and c["y0"] - a["y0"] > 7 * u:
                    return 3
    return 0


def purify(img: Image.Image) -> bytes:
    """Feature-squeeze + metadata strip. Returns PNG bytes safe to forward to a VLM."""
    rgb = img.convert("RGBA")
    flat = Image.new("RGB", rgb.size, (255, 255, 255))
    flat.paste(rgb, mask=rgb.split()[3])
    out = ImageOps.posterize(flat.filter(ImageFilter.MedianFilter(3)), 5)
    buf = io.BytesIO()
    out.save(buf, "PNG", optimize=True)  # no EXIF / text chunks are written
    return buf.getvalue()


# --------------------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------------------
@dataclass
class VisionReport:
    verdict: Verdict
    score: float
    findings: list[Finding] = field(default_factory=list)
    ocr_text: str = ""
    hidden_text: str = ""
    qr_payloads: list[str] = field(default_factory=list)
    sanitized_png: bytes | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"verdict": self.verdict.value, "score": round(self.score, 4), "findings": [f.as_dict() for f in self.findings],
                "qr_payloads": self.qr_payloads, "meta": self.meta, "ocr_chars": len(self.ocr_text)}


def _trailing(data: bytes, fmt: str) -> bytes:
    if fmt == "PNG":
        i = data.rfind(b"IEND")
        return data[i + 8 :] if i >= 0 else b""
    if fmt == "JPEG":
        i = data.rfind(b"\xff\xd9")
        return data[i + 2 :] if i >= 0 else b""
    return b""


class VisionScanner:
    def __init__(self, settings: ShieldSettings, *, ocr: OcrEngine | None = None, guard: OnnxVisualGuard | None = None) -> None:
        self.s = settings
        self.ocr: OcrEngine = ocr or TesseractCliOcr()
        self.guard = guard or OnnxVisualGuard(settings.visual_model_path)

    def _text_findings(self, text: str, rule: str, cat: C, score_hit: float, src: str) -> tuple[list[Finding], bool]:
        norm = normalize(text, max_chars=20_000, source=src)
        fs = [f for f in scan_instructions(norm.text, TrustLevel.UNTRUSTED, source=src) if f.score >= 0.5]
        fs += [f for f in norm.findings if f.category in (C.TOKEN_SMUGGLING, C.HOMOGLYPH)]
        if fs:
            top = max(f.score for f in fs)
            return [Finding(cat, rule, max(top, score_hit), "; ".join(f.rule for f in fs[:3]), source=src)], True
        return [], False

    def scan(self, data: bytes) -> VisionReport:
        try:
            return self._scan(data)
        except Exception as e:  # noqa: BLE001 - zero trust: an image we cannot analyse is not forwarded
            f = Finding(C.INTERNAL, "vision.scan_error", 1.0, f"{type(e).__name__}: {e}"[:200], source="vision")
            return VisionReport(Verdict.BLOCK, 1.0, [f])

    async def scan_async(self, data: bytes) -> VisionReport:
        return await asyncio.to_thread(self.scan, data)

    def _scan(self, data: bytes) -> VisionReport:
        s = self.s
        F: list[Finding] = []
        if not data or len(data) > s.max_image_bytes:
            return VisionReport(Verdict.BLOCK, 1.0, [Finding(C.RESOURCE, "vision.size", 1.0, f"image size {len(data)} outside limits", source="vision")])
        Image.MAX_IMAGE_PIXELS = s.max_image_pixels
        try:
            probe = Image.open(io.BytesIO(data))
            probe.verify()
            img = Image.open(io.BytesIO(data))
            fmt = img.format or ""
            if fmt not in ALLOWED_FORMATS:
                raise ValueError(f"format {fmt!r} not allowed")
            if img.width * img.height > s.max_image_pixels:
                raise ValueError("too many pixels")
            frames = getattr(img, "n_frames", 1)
            img.load()
        except (Image.DecompressionBombError, Image.DecompressionBombWarning) as e:
            return VisionReport(Verdict.BLOCK, 1.0, [Finding(C.RESOURCE, "vision.decompression_bomb", 1.0, str(e)[:120], source="vision")])
        except Exception as e:  # noqa: BLE001
            return VisionReport(Verdict.BLOCK, 1.0, [Finding(C.INTERNAL, "vision.undecodable", 1.0, f"{type(e).__name__}: {e}"[:160], source="vision")])
        if frames > 1:
            F.append(Finding(C.VISUAL_ADVERSARIAL, "vision.multi_frame", 0.3, f"{frames} frames; only frame 0 analysed and forwarded", source="vision"))

        # -- 1. container / metadata
        trail = _trailing(data, fmt)
        if len(trail) > 4:
            txt = trail.decode("utf-8", "ignore")
            F.append(Finding(C.VISUAL_STEGANOGRAPHY, "vision.trailing_data", 0.55, f"{len(trail)} bytes after image end", source="vision"))
            tf, _ = self._text_findings(txt, "vision.trailing_instruction", C.INDIRECT_INJECTION, 0.9, "vision:trailer")
            F += tf
        meta_strings: list[str] = []
        for v in list(img.info.values()):
            if isinstance(v, (str, bytes)) and len(v) > 4:
                meta_strings.append(v.decode("utf-8", "ignore") if isinstance(v, bytes) else v)
        try:
            for v in img.getexif().values():
                if isinstance(v, (str, bytes)) and len(v) > 4:
                    meta_strings.append(v.decode("utf-8", "ignore") if isinstance(v, bytes) else v)
        except Exception:  # noqa: BLE001
            pass
        for m in meta_strings[:50]:
            mf, hit = self._text_findings(m, "vision.metadata_instruction", C.INDIRECT_INJECTION, 0.9, "vision:metadata")
            F += mf

        rgba = np.asarray(img.convert("RGBA"))
        gray = np.asarray(img.convert("L"))
        meta: dict[str, Any] = {"format": fmt, "width": img.width, "height": img.height, "frames": frames}

        # -- 3. steganography
        for tag, payload in stego_payloads(rgba):
            if payload.startswith("magic:"):
                F.append(Finding(C.VISUAL_STEGANOGRAPHY, "stego.lsb_file", 0.85, f"LSB stream ({tag}) starts with file magic", source="vision"))
            else:
                tf, hit = self._text_findings(payload, "stego.lsb_instruction", C.VISUAL_STEGANOGRAPHY, 0.7, "vision:lsb")
                F += tf or [Finding(C.VISUAL_STEGANOGRAPHY, "stego.lsb_text", 0.7, f"printable text in LSB stream ({tag}): {payload[:40]!r}", source="vision")]
        mean0, ag0, ag1 = lsb_decorrelation(rgba)
        meta.update(lsb_mean=round(mean0, 3), lsb_agree=round(ag0, 3), bit1_agree=round(ag1, 3))
        if ag1 >= 0.80 and 0.45 <= ag0 <= 0.55 and 0.45 <= mean0 <= 0.55:
            F.append(Finding(C.VISUAL_STEGANOGRAPHY, "stego.lsb_decorrelated", 0.5, "LSB plane is random while higher planes are structured", source="vision"))

        # -- 2. OCR (visible + amplified)
        visible_text, hidden_text, ocr_hit_visible = "", "", False
        mode_frac, faint_ratio, bg = faint_structure(gray)
        meta.update(mode_fraction=round(mode_frac, 3), faint_ratio=round(faint_ratio, 5))
        if s.require_ocr and not self.ocr.available:
            F.append(Finding(C.INTERNAL, "vision.ocr_unavailable", 0.95, "OCR required but unavailable (fail closed)", source="vision"))
        elif self.ocr.available:
            work = img.convert("L")
            if max(work.size) < 900:
                work = work.resize((work.width * 2, work.height * 2), Image.LANCZOS)
            visible_text = self.ocr.read(work)
            vf, ocr_hit_visible = self._text_findings(visible_text, "vision.typographic_injection", C.INDIRECT_INJECTION, 0.85, "vision:ocr")
            F += vf
        if faint_ratio > 0.001:
            F.append(Finding(C.VISUAL_HIDDEN_TEXT, "vision.faint_structure", 0.5, f"isolated low-contrast structure ({faint_ratio:.4f} of pixels)", source="vision"))
            if self.ocr.available:
                amp = amplify_faint(gray, bg)
                if max(amp.size) < 900:
                    amp = amp.resize((amp.width * 2, amp.height * 2), Image.LANCZOS)
                hidden_text = self.ocr.read(amp)
                hf, hit = self._text_findings(hidden_text, "vision.hidden_text_instruction", C.VISUAL_HIDDEN_TEXT, 0.95, "vision:ocr-amplified")
                if hit and not ocr_hit_visible:
                    F += hf

        # -- 4. QR codes
        qr: list[str] = []
        n_finders = find_qr_finder_patterns(gray)
        meta["qr_finder_clusters"] = n_finders
        if n_finders >= 3:
            decoded = _decode_qr(img)
            if decoded is None:
                F.append(Finding(C.VISUAL_QR, "qr.present_undecoded", 0.6, "QR code present but no decoder installed; payload not inspectable", source="vision"))
            elif not decoded:
                F.append(Finding(C.VISUAL_QR, "qr.present_unreadable", 0.5, "QR-like pattern detected but not decodable", source="vision"))
            for p in decoded or []:
                qr.append(p)
                F.append(Finding(C.VISUAL_QR, "qr.payload", 0.45 if p.lower().startswith(("http://", "https://")) else 0.3, f"QR payload: {p[:60]!r}", source="vision"))
                tf, _ = self._text_findings(p, "qr.instruction", C.INDIRECT_INJECTION, 0.95, "vision:qr")
                F += tf

        # -- 5. adversarial perturbation
        sigma = noise_sigma(gray)
        hist = np.bincount(gray.ravel(), minlength=256)
        window = float(np.convolve(hist, np.ones(9), mode="valid").max() / gray.size)
        meta.update(noise_sigma=round(sigma, 3), narrow_band_fraction=round(window, 3))
        if sigma > 1.5 and window >= 0.5:
            F.append(Finding(C.VISUAL_ADVERSARIAL, "vision.noise_on_flat", min(0.45 + 0.05 * (sigma - 1.5), 0.7),
                             f"sigma={sigma:.2f} on a narrow-histogram image", source="vision"))
        if self.guard.available:
            probs = self.guard.predict(img)
            meta["cnn"] = {k: round(v, 3) for k, v in probs.items()}
            if probs["adversarial"] >= 0.5:
                F.append(Finding(C.VISUAL_ADVERSARIAL, "cnn.adversarial", min(0.95, 0.5 + probs["adversarial"] / 2), f"p={probs['adversarial']:.2f}", source="cnn"))
            if probs["visual_injection"] >= 0.5:
                F.append(Finding(C.VISUAL_HIDDEN_TEXT, "cnn.visual_injection", min(0.95, 0.5 + probs["visual_injection"] / 2), f"p={probs['visual_injection']:.2f}", source="cnn"))
        elif s.require_cnn:
            F.append(Finding(C.INTERNAL, "vision.cnn_unavailable", 0.95, "visual guard model required but not loaded (fail closed)", source="vision"))

        score = noisy_or(f.score for f in F)
        if score >= s.block_threshold:
            verdict, png = Verdict.BLOCK, None
        else:
            png = purify(img)
            verdict = Verdict.SANITIZED if score >= s.heal_threshold else Verdict.ALLOW
        return VisionReport(verdict, score, F, visible_text, hidden_text, qr, png, meta)
