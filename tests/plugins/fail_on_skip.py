def pytest_addoption(parser):
    parser.addoption(
        "--fail-on-skip",
        action="store_true",
        default=False,
        help="Fail the test session if any test is skipped.",
    )


def pytest_sessionstart(session):
    session._skipped_reports = []


def pytest_runtest_logreport(report):
    if report.skipped:
        report.session._skipped_reports.append(report)


def pytest_sessionfinish(session, exitstatus):
    if session.config.getoption("--fail-on-skip") and session._skipped_reports:
        terminal = session.config.pluginmanager.get_plugin("terminalreporter")
        if terminal:
            terminal.write_sep("=", "Skipped tests are forbidden in this CI job")
            for report in session._skipped_reports:
                terminal.write_line(f"{report.nodeid}: {report.longrepr}")
        session.exitstatus = 1
