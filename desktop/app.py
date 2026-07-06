"""Desktop control panel (PySide6) — the operator GUI for the Kali MCP server.

A THIN view over desktop.backend (CLAUDE.md desktop decision 2026-07-06):
  * displays the honest platform snapshot (read-only — never scans to fill the screen);
  * one action, Run arp_watch, triggered through the audited + scope-gated wrapper in the
    container, on a worker thread so the window never freezes.

No network port is opened; this is a native window. All business logic lives in
desktop.backend — this file only builds widgets and moves data into them.
"""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from desktop import backend
from desktop.backend import DockerScanRunner, ScanOutcome, ScanRunner, ViewModel

# Accessible palette — mirrors the HTML dashboard. Status is NEVER colour-alone: every
# level pairs this colour with a symbol + text label (CLAUDE.md desktop decision).
_BG = "#0a0e14"
_FG = "#f0f6fc"
_MUTED = "#9aa4b2"
_PANEL = "#141b26"
_LEVEL_COLOR = {
    "rogue": "#ff6b6b",
    "all_clear": "#3fb950",
    "review": "#e3b341",
    "no_data": "#8b98a9",
    "whitelist_error": "#e3b341",
}
_STALE_COLOR = "#e3b341"
_BASE_PT = 13  # ≥ large; Qt point sizes render ~19px+ at default DPI


class ScanWorker(QThread):
    """Runs one arp_watch off the UI thread; emits the honest outcome when done."""

    done = Signal(object)  # ScanOutcome

    def __init__(self, runner: ScanRunner, interface: str) -> None:
        super().__init__()
        self._runner = runner
        self._interface = interface

    def run(self) -> None:  # QThread entry point
        outcome = self._runner.run_arp_watch(interface=self._interface)
        self.done.emit(outcome)


def _panel(title: str) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame()
    frame.setStyleSheet(f"QFrame {{ background: {_PANEL}; border-radius: 8px; }}")
    lay = QVBoxLayout(frame)
    lay.setContentsMargins(16, 12, 16, 14)
    heading = QLabel(title)
    heading.setStyleSheet(f"color: {_MUTED}; font-size: {_BASE_PT - 2}pt; font-weight: 600;")
    lay.addWidget(heading)
    return frame, lay


class MainWindow(QMainWindow):
    def __init__(self, runner: ScanRunner | None = None) -> None:
        super().__init__()
        self._runner = runner or DockerScanRunner()
        self._worker: ScanWorker | None = None

        self.setWindowTitle("Kali MCP — Network Watch")
        self.setStyleSheet(
            f"QWidget {{ background: {_BG}; color: {_FG}; "
            f"font-family: 'DejaVu Sans Mono', monospace; font-size: {_BASE_PT}pt; }}"
        )

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(20, 18, 20, 18)
        outer.setSpacing(14)

        # --- action bar -----------------------------------------------------------
        bar = QHBoxLayout()
        bar.addWidget(self._muted_label("Interface:"))
        self.iface_edit = QLineEdit("wlan0")
        self.iface_edit.setFixedWidth(140)
        self.iface_edit.setStyleSheet(
            f"QLineEdit {{ background: {_PANEL}; color: {_FG}; border: 1px solid #2b3546; "
            "border-radius: 6px; padding: 6px 8px; }"
        )
        bar.addWidget(self.iface_edit)
        self.scan_btn = QPushButton("▶  Run arp_watch")
        self.scan_btn.clicked.connect(self._on_scan)
        self.refresh_btn = QPushButton("⟳  Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        for b in (self.scan_btn, self.refresh_btn):
            b.setStyleSheet(
                f"QPushButton {{ background: {_PANEL}; color: {_FG}; border: 1px solid #2b3546; "
                "border-radius: 6px; padding: 8px 14px; font-weight: 600; } "
                "QPushButton:disabled { color: #5a6472; }"
            )
        bar.addWidget(self.scan_btn)
        bar.addWidget(self.refresh_btn)
        bar.addStretch(1)
        outer.addLayout(bar)

        # --- status banner --------------------------------------------------------
        self.stale_label = QLabel()
        self.stale_label.setVisible(False)
        self.stale_label.setStyleSheet(
            f"background: {_STALE_COLOR}; color: #14110a; border-radius: 6px; "
            f"padding: 8px 12px; font-weight: 700; font-size: {_BASE_PT}pt;"
        )
        outer.addWidget(self.stale_label)

        self.banner = QLabel()
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet(f"border-radius: 10px; padding: 18px 20px;")
        outer.addWidget(self.banner)

        # --- info grid ------------------------------------------------------------
        grid = QGridLayout()
        grid.setSpacing(12)
        counts_frame, self.counts_lay = _panel("DEVICES (last scan)")
        wl_frame, self.wl_lay = _panel("WHITELIST")
        tools_frame, self.tools_lay = _panel("TOOLS INSTALLED")
        time_frame, self.time_lay = _panel("SNAPSHOT")
        grid.addWidget(counts_frame, 0, 0)
        grid.addWidget(wl_frame, 0, 1)
        grid.addWidget(tools_frame, 1, 0)
        grid.addWidget(time_frame, 1, 1)
        outer.addLayout(grid)

        # --- rogues + activity (scrollable) --------------------------------------
        rogue_frame, self.rogue_lay = _panel("ROGUE DEVICES")
        outer.addWidget(rogue_frame)
        audit_frame, self.audit_lay = _panel("RECENT ACTIVITY (audit log)")
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(audit_frame)
        scroll.setStyleSheet("QScrollArea { border: none; }")
        scroll.setMinimumHeight(150)
        outer.addWidget(scroll)

        self.status_line = self._muted_label("")
        outer.addWidget(self.status_line)

        self.resize(920, 860)

    # ---------------------------------------------------------------- helpers
    def _muted_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {_MUTED};")
        return lbl

    def _clear(self, layout: QVBoxLayout) -> None:
        # keep the panel heading (index 0); drop the rest. setParent(None) removes the
        # widget from display IMMEDIATELY (deleteLater alone is deferred to the event
        # loop, which would let a stale row overlap a fresh one on a same-tick re-render).
        while layout.count() > 1:
            item = layout.takeAt(1)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()

    def _row(self, layout: QVBoxLayout, text: str, *, color: str | None = None) -> None:
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setStyleSheet(f"color: {color or _FG};")
        layout.addWidget(lbl)

    # ---------------------------------------------------------------- rendering
    def apply_view(self, vm: ViewModel) -> None:
        """Move a ViewModel into the widgets. Pure view — no data access here."""
        color = _LEVEL_COLOR.get(vm.level, _MUTED)
        self.banner.setText(f"{vm.symbol}  {vm.label}\n{vm.headline}")
        # Dark levels get dark text on the bright colour; muted no-data stays light-on-dark.
        text_col = "#0a0e14" if vm.level in ("all_clear", "rogue", "review", "whitelist_error") else _FG
        bg = color if vm.level != "no_data" else _PANEL
        self.banner.setStyleSheet(
            f"background: {bg}; color: {text_col}; border-radius: 10px; padding: 18px 20px; "
            f"font-size: {_BASE_PT + 6}pt; font-weight: 800;"
        )

        if vm.stale and vm.level not in ("no_data", "whitelist_error"):
            self.stale_label.setText(f"⏱  DATA IS {vm.age_human} OLD — re-run arp_watch (a stale all-clear is not a current all-clear)")
            self.stale_label.setVisible(True)
        else:
            self.stale_label.setVisible(False)

        self._clear(self.counts_lay)
        c = vm.counts
        self._row(self.counts_lay, f"✓ KNOWN        {c['known']}", color=_LEVEL_COLOR['all_clear'])
        self._row(self.counts_lay, f"⚠ ROGUE        {c['rogue']}", color=_LEVEL_COLOR['rogue'] if c['rogue'] else _MUTED)
        self._row(self.counts_lay, f"≠ IP MISMATCH  {c['ip_mismatch']}", color=_LEVEL_COLOR['review'] if c['ip_mismatch'] else _MUTED)
        self._row(self.counts_lay, f"○ ABSENT       {c['absent']}", color=_MUTED)

        self._clear(self.wl_lay)
        if vm.whitelist.get("loaded") is False:
            self._row(self.wl_lay, "⚠ could not load", color=_LEVEL_COLOR['whitelist_error'])
            self._row(self.wl_lay, str(vm.whitelist.get("error") or ""), color=_MUTED)
        else:
            self._row(self.wl_lay, f"✓ loaded — {vm.whitelist.get('device_count', 0)} known device(s)", color=_LEVEL_COLOR['all_clear'])

        self._clear(self.tools_lay)
        self._row(self.tools_lay, vm.tools_installed)

        self._clear(self.time_lay)
        self._row(self.time_lay, f"generated  {vm.generated_at or '—'}", color=_MUTED)
        self._row(self.time_lay, f"last scan  {vm.as_of or '—'}", color=_MUTED)

        self._clear(self.rogue_lay)
        if vm.rogues:
            for r in vm.rogues:
                self._row(self.rogue_lay, f"⚠  {r.get('ip', '?'):<16} {r.get('mac', '?')}   {r.get('vendor') or ''}", color=_LEVEL_COLOR['rogue'])
        else:
            self._row(self.rogue_lay, "none in the last scan", color=_MUTED)

        self._clear(self.audit_lay)
        if vm.audit_tail:
            for a in reversed(vm.audit_tail):
                self._row(self.audit_lay, f"{a.get('timestamp', '')[:19]}  {a.get('tool', ''):<10} {a.get('status', '')}", color=_MUTED)
        else:
            self._row(self.audit_lay, "no commands logged yet", color=_MUTED)

    def refresh(self) -> None:
        """Read real state and render it. Read-only — never triggers a scan."""
        try:
            snap, staleness = backend.snapshot()
        except Exception as exc:  # noqa: BLE001 — a read failure is shown, never hidden
            self.status_line.setText(f"could not read state: {type(exc).__name__}: {exc}")
            return
        self.apply_view(backend.build_view_model(snap, staleness))
        self.status_line.setText("state refreshed (read-only)")

    # ---------------------------------------------------------------- actions
    def _on_scan(self) -> None:
        iface = self.iface_edit.text().strip() or "wlan0"
        self.scan_btn.setEnabled(False)
        self.status_line.setText(f"running arp_watch on {iface} (through the audited container wrapper)…")
        self._worker = ScanWorker(self._runner, iface)
        self._worker.done.connect(self._on_scan_done)
        self._worker.start()

    def _on_scan_done(self, outcome: ScanOutcome) -> None:
        self.scan_btn.setEnabled(True)
        if outcome.ok:
            self.status_line.setText(f"scan complete — {outcome.verdict}")
        else:
            # Honest failure: the real error, never a fake 'all clear'.
            self.status_line.setText(f"scan did NOT complete: {outcome.error}")
        self.refresh()  # re-read whatever real state the scan persisted (or didn't)


def build_window(runner: ScanRunner | None = None, *, do_refresh: bool = True) -> MainWindow:
    """Construct the window (optionally populated with real state). Factored out so a
    headless smoke-test / screenshot can build it without an event loop."""
    backend.ensure_paths()
    win = MainWindow(runner=runner)
    if do_refresh:
        win.refresh()
    return win


def main() -> int:
    backend.ensure_paths()
    app = QApplication(sys.argv)
    win = build_window()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
