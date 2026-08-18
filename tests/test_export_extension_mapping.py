"""Regression test for CLI output-extension -> exporter format mapping.

The CLI used to derive the export format as ``ext.lstrip(".")``, so ``-o
report.md`` sent ``format=md`` and ``-o report.mtgx`` sent ``format=mtgx``.
Neither matches a registered exporter (``markdown`` / ``maltego``), so the
export endpoint returned 422 and no file was written.  This pins every
supported extension to a real exporter name.
"""
from __future__ import annotations

from backend.exporters import EXPORTERS
from cli.main import _EXTENSION_TO_FORMAT


def test_every_export_extension_maps_to_a_registered_exporter():
    for ext, fmt in _EXTENSION_TO_FORMAT.items():
        assert fmt in EXPORTERS, f"{ext} -> {fmt!r} is not a registered exporter"


def test_markdown_and_maltego_extensions_map_to_their_exporter_names():
    assert _EXTENSION_TO_FORMAT[".md"] == "markdown"
    assert _EXTENSION_TO_FORMAT[".mtgx"] == "maltego"
