"""Desktop control panel (PySide6) — the operator GUI for the Kali MCP server.

A THIN view over desktop.backend (CLAUDE.md desktop decision 2026-07-06):
  * displays the honest platform snapshot (read-only — never scans to fill the screen);
  * scan actions (Run arp_watch, Run nmap) go through the audited + scope-gated wrapper in
    the container, on a worker thread so the window never freezes;
  * Generate dashboard writes the self-contained HTML from produced state in-process — a
    read + write-a-file action, not a scan (see DashboardOutcome), also off the UI thread.

No network port is opened; this is a native window. All business logic lives in
desktop.backend — this file only builds widgets and moves data into them.
"""

from __future__ import annotations

import sys

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
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
from desktop.backend import (
    NMAP_SCAN_TYPES,
    DashboardOutcome,
    DockerScanRunner,
    NmapOutcome,
    ScanOutcome,
    ScanRunner,
    ViewModel,
)

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

    def __init__(self, runner: ScanRunner, interface: str, target_range: str | None = None) -> None:
        super().__init__()
        self._runner = runner
        self._interface = interface
        self._target_range = target_range

    def run(self) -> None:  # QThread entry point
        # target_range is scope-checked inside run_arp_watch (off this UI thread), so an
        # out-of-scope range comes back as an honest ScanOutcome error, never a freeze.
        outcome = self._runner.run_arp_watch(
            interface=self._interface, target_range=self._target_range
        )
        self.done.emit(outcome)


class NmapWorker(QThread):
    """Runs one nmap scan off the UI thread; emits the honest NmapOutcome when done."""

    done = Signal(object)  # NmapOutcome

    def __init__(self, runner: ScanRunner, target: str, scan_type: str, ports: str | None) -> None:
        super().__init__()
        self._runner = runner
        self._target = target
        self._scan_type = scan_type
        self._ports = ports

    def run(self) -> None:  # QThread entry point
        # The target is scope-checked inside run_nmap (off this UI thread) — an out-of-scope
        # target comes back as an honest NmapOutcome error, never a freeze and never a run.
        outcome = self._runner.run_nmap(
            target=self._target, scan_type=self._scan_type, ports=self._ports
        )
        self.done.emit(outcome)


class DashboardWorker(QThread):
    """Generates the self-contained dashboard off the UI thread; emits the honest
    DashboardOutcome. In-process (no container) — see backend.DashboardOutcome."""

    done = Signal(object)  # DashboardOutcome

    def run(self) -> None:  # QThread entry point
        self.done.emit(backend.run_generate_dashboard())


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
        self._nmap_worker: NmapWorker | None = None
        self._last_nmap: NmapOutcome | None = None
        self._dash_worker: DashboardWorker | None = None
        self._last_dashboard: DashboardOutcome | None = None

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
        bar.addWidget(self._muted_label("Range:"))
        self.range_edit = QLineEdit()
        self.range_edit.setFixedWidth(190)
        self.range_edit.setPlaceholderText("whole segment (optional)")
        self.range_edit.setStyleSheet(
            f"QLineEdit {{ background: {_PANEL}; color: {_FG}; border: 1px solid #2b3546; "
            "border-radius: 6px; padding: 6px 8px; } "
            f"QLineEdit::placeholder {{ color: #5a6472; }}"
        )
        # Enter in either field triggers the scan — same as clicking the button.
        self.iface_edit.returnPressed.connect(self._on_scan)
        self.range_edit.returnPressed.connect(self._on_scan)
        bar.addWidget(self.range_edit)
        self.scan_btn = QPushButton("▶  Run arp_watch")
        self.scan_btn.clicked.connect(self._on_scan)
        self.refresh_btn = QPushButton("⟳  Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        # Global, no-input action: write the self-contained dashboard from produced state.
        self.dash_btn = QPushButton("▤  Generate dashboard")
        self.dash_btn.clicked.connect(self._on_generate_dashboard)
        for b in (self.scan_btn, self.refresh_btn, self.dash_btn):
            b.setStyleSheet(
                f"QPushButton {{ background: {_PANEL}; color: {_FG}; border: 1px solid #2b3546; "
                "border-radius: 6px; padding: 8px 14px; font-weight: 600; } "
                "QPushButton:disabled { color: #5a6472; }"
            )
        bar.addWidget(self.scan_btn)
        bar.addWidget(self.refresh_btn)
        bar.addWidget(self.dash_btn)
        bar.addStretch(1)
        outer.addLayout(bar)

        # --- nmap action bar ------------------------------------------------------
        # A second gated action: scan a chosen host/CIDR with nmap. The target is
        # scope-checked before any container runs (out-of-scope -> instant honest refusal).
        field_css = (
            f"background: {_PANEL}; color: {_FG}; border: 1px solid #2b3546; "
            "border-radius: 6px; padding: 6px 8px;"
        )
        nbar = QHBoxLayout()
        nbar.addWidget(self._muted_label("nmap target:"))
        self.nmap_target_edit = QLineEdit()
        self.nmap_target_edit.setFixedWidth(180)
        self.nmap_target_edit.setPlaceholderText("192.168.50.1")
        self.nmap_target_edit.setStyleSheet(f"QLineEdit {{ {field_css} }}")
        nbar.addWidget(self.nmap_target_edit)
        nbar.addWidget(self._muted_label("type:"))
        self.nmap_type_combo = QComboBox()
        self.nmap_type_combo.addItems(list(NMAP_SCAN_TYPES))
        self.nmap_type_combo.setStyleSheet(f"QComboBox {{ {field_css} }}")
        nbar.addWidget(self.nmap_type_combo)
        nbar.addWidget(self._muted_label("ports:"))
        self.nmap_ports_edit = QLineEdit()
        self.nmap_ports_edit.setFixedWidth(120)
        self.nmap_ports_edit.setPlaceholderText("default")
        self.nmap_ports_edit.setStyleSheet(f"QLineEdit {{ {field_css} }}")
        nbar.addWidget(self.nmap_ports_edit)
        self.nmap_btn = QPushButton("▶  Run nmap")
        self.nmap_btn.clicked.connect(self._on_nmap)
        self.nmap_btn.setStyleSheet(
            f"QPushButton {{ background: {_PANEL}; color: {_FG}; border: 1px solid #2b3546; "
            "border-radius: 6px; padding: 8px 14px; font-weight: 600; } "
            "QPushButton:disabled { color: #5a6472; }"
        )
        self.nmap_target_edit.returnPressed.connect(self._on_nmap)
        self.nmap_ports_edit.returnPressed.connect(self._on_nmap)
        nbar.addWidget(self.nmap_btn)
        nbar.addStretch(1)
        outer.addLayout(nbar)

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

        # --- nmap result ----------------------------------------------------------
        nmap_frame, self.nmap_lay = _panel("LAST NMAP SCAN (this session)")
        outer.addWidget(nmap_frame)

        # --- dashboard result -----------------------------------------------------
        dash_frame, self.dash_lay = _panel("DASHBOARD (self-contained HTML)")
        outer.addWidget(dash_frame)

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

        self.apply_nmap_outcome(None)  # seed "no nmap scan run yet"
        self.apply_dashboard_outcome(None)  # seed "no dashboard generated yet"
        self.resize(960, 1040)

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

    def apply_nmap_outcome(self, outcome: NmapOutcome | None) -> None:
        """Render the last nmap scan honestly. No scan yet, a failed scan, and a clean
        scan-with-no-open-ports are three DISTINCT states — none is dressed up as another."""
        self._clear(self.nmap_lay)
        if outcome is None:
            self._row(self.nmap_lay, "no nmap scan run yet — enter a target and Run nmap", color=_MUTED)
            return
        if not outcome.ok:
            # Honest failure: the real reason (out of scope, docker missing, nmap error), never
            # a fabricated 'nothing open'.
            self._row(self.nmap_lay, f"⚠  scan did NOT complete: {outcome.error}", color=_LEVEL_COLOR["rogue"])
            return

        self._row(self.nmap_lay, f"✓  {outcome.summary}", color=_LEVEL_COLOR["all_clear"])
        any_open = False
        for host in outcome.hosts:
            open_ports = [p for p in (host.get("ports") or []) if p.get("state") == "open"]
            if not open_ports:
                continue
            any_open = True
            self._row(self.nmap_lay, f"  {host.get('address') or '?'}", color=_FG)
            for p in open_ports:
                detail = " ".join(
                    x for x in (p.get("service"), p.get("product"), p.get("version")) if x
                )
                self._row(self.nmap_lay, f"      {p.get('portid')}/{p.get('protocol')}   {detail}", color=_MUTED)
        if not any_open:
            # A real, successful scan that found no open ports — NOT an error, NOT invented.
            self._row(self.nmap_lay, "  no open ports in the result", color=_MUTED)

    def apply_dashboard_outcome(self, outcome: DashboardOutcome | None) -> None:
        """Render the last dashboard generation honestly. Not-run-yet, a failed generation
        (nothing written), and a written file are three DISTINCT states — a failure is never
        dressed up as a written file, and a file built on a stale scan says so."""
        self._clear(self.dash_lay)
        if outcome is None:
            self._row(self.dash_lay, "no dashboard generated yet — click Generate dashboard", color=_MUTED)
            return
        if not outcome.ok:
            # Honest failure: the real reason, and NO file was written.
            self._row(self.dash_lay, f"⚠  not generated: {outcome.error}", color=_LEVEL_COLOR["rogue"])
            return
        self._row(self.dash_lay, f"✓  {outcome.summary or 'dashboard written'}", color=_LEVEL_COLOR["all_clear"])
        self._row(self.dash_lay, f"  file: {outcome.path}", color=_FG)
        if outcome.stale:
            self._row(
                self.dash_lay,
                f"  ⏱ underlying scan is {outcome.age_human} old — the dashboard stamps this; it is NOT current data",
                color=_STALE_COLOR,
            )
        self._row(self.dash_lay, "  open it from disk — self-contained (no server, no port)", color=_MUTED)

    def refresh(self) -> None:
        """Read real state and render it. Read-only — never triggers a scan."""
        try:
            snap, staleness = backend.snapshot()
        except Exception as exc:  # noqa: BLE001 — a read failure is shown, never hidden
            self.status_line.setText(f"could not read state: {type(exc).__name__}: {exc}")
            return
        self.apply_view(backend.build_view_model(snap, staleness))
        # nmap + dashboard results live in-session (not part of the persisted snapshot) —
        # re-render the last of each so a Refresh of the display doesn't blank them.
        self.apply_nmap_outcome(self._last_nmap)
        self.apply_dashboard_outcome(self._last_dashboard)
        self.status_line.setText("state refreshed (read-only)")

    # ---------------------------------------------------------------- actions
    def _on_scan(self) -> None:
        # A scan already in flight? Ignore re-triggers (button is disabled, but returnPressed
        # can still fire) so we never start two workers over one another.
        if self._worker is not None and self._worker.isRunning():
            return
        iface = self.iface_edit.text().strip() or "wlan0"
        target_range = self.range_edit.text().strip() or None
        self.scan_btn.setEnabled(False)
        where = f"{iface}, range {target_range}" if target_range else f"{iface} (whole segment)"
        self.status_line.setText(f"running arp_watch on {where} (through the audited container wrapper)…")
        self._worker = ScanWorker(self._runner, iface, target_range)
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

    def _on_nmap(self) -> None:
        # A scan already in flight? Ignore re-triggers so we never start two workers at once.
        if self._nmap_worker is not None and self._nmap_worker.isRunning():
            return
        target = self.nmap_target_edit.text().strip()
        if not target:
            self.status_line.setText("nmap needs a target — an IP/host on your own network")
            return
        scan_type = self.nmap_type_combo.currentText()
        ports = self.nmap_ports_edit.text().strip() or None
        self.nmap_btn.setEnabled(False)
        self.status_line.setText(
            f"running nmap ({scan_type}) on {target} (through the audited container wrapper)…"
        )
        self._nmap_worker = NmapWorker(self._runner, target, scan_type, ports)
        self._nmap_worker.done.connect(self._on_nmap_done)
        self._nmap_worker.start()

    def _on_nmap_done(self, outcome: NmapOutcome) -> None:
        self.nmap_btn.setEnabled(True)
        self._last_nmap = outcome
        self.apply_nmap_outcome(outcome)
        if outcome.ok:
            self.status_line.setText(f"nmap complete — {outcome.summary}")
        else:
            self.status_line.setText(f"nmap did NOT complete: {outcome.error}")

    def _on_generate_dashboard(self) -> None:
        # Already generating? Ignore re-triggers so we never start two workers at once.
        if self._dash_worker is not None and self._dash_worker.isRunning():
            return
        self.dash_btn.setEnabled(False)
        self.status_line.setText("generating dashboard from produced state (read-only, no scan)…")
        self._dash_worker = DashboardWorker()
        self._dash_worker.done.connect(self._on_dashboard_done)
        self._dash_worker.start()

    def _on_dashboard_done(self, outcome: DashboardOutcome) -> None:
        self.dash_btn.setEnabled(True)
        self._last_dashboard = outcome
        self.apply_dashboard_outcome(outcome)
        if outcome.ok:
            self.status_line.setText(f"dashboard written to {outcome.path}")
        else:
            self.status_line.setText(f"dashboard NOT generated: {outcome.error}")


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
