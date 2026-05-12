def pytest_addoption(parser):
    parser.addoption(
        "--fail-on-skip",
        action="store_true",
        default=False,
        help="Fail the test session if any test is skipped.",
    )


def pytest_sessionfinish(session, exitstatus):
    if not session.config.getoption("--fail-on-skip"):
        return

    terminal = session.config.pluginmanager.get_plugin("terminalreporter")
    skipped = terminal.stats.get("skipped", []) if terminal is not None else []

    if skipped:
        if terminal is not None:
            terminal.write_sep("=", "Skipped tests are forbidden in this CI job")
            for report in skipped:
                terminal.write_line(f"{report.nodeid}: {report.longrepr}")
        session.exitstatus = 1
