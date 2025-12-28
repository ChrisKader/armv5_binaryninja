from __future__ import annotations

import types

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addini(
        "status_alignment_column",
        "Column at which to render test outcomes",
        default="72",
    )


def pytest_configure(config: pytest.Config) -> None:
    reporter = config.pluginmanager.getplugin("terminalreporter")
    if reporter is None:
        return

    try:
        column = int(config.getini("status_alignment_column"))
    except ValueError:
        column = 72
    column = max(column, 10)

    def _pad(text: str) -> str:
        if len(text) >= column:
            return text + " "
        return text + " " * (column - len(text))

    def aligned_write_ensure_prefix(self, prefix, extra="", **kwargs):  # type: ignore[override]
        if self.currentfspath != prefix:
            self._tw.line()
            self.currentfspath = prefix
            self._tw.write(_pad(prefix))
        else:
            current = self._tw.width_of_current_line

            if current < column:
                self._tw.write(" " * (column - current))
        if extra:
            self._tw.write(extra, **kwargs)
            self.currentfspath = -2

    def aligned_write_fspath_result(self, nodeid, res, **markup):  # type: ignore[override]
        self.ensure_newline()
        formatted = f"{nodeid:<{column}} {res}"
        self._tw.write(formatted, **markup)
        self._tw.write("\n")

    reporter.write_ensure_prefix = types.MethodType(aligned_write_ensure_prefix, reporter)
    reporter.write_fspath_result = types.MethodType(aligned_write_fspath_result, reporter)
