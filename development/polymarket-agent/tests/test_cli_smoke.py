from agent import cli


def test_cli_module_exposes_main():
    """The cli module has a `main` callable usable as a console entrypoint."""
    assert callable(cli.main)


def test_cli_main_handles_unknown_subcommand(capsys):
    """An unknown subcommand exits non-zero with usage info on stderr."""
    rc = cli.main(["nonexistent"])
    assert rc != 0
    captured = capsys.readouterr()
    assert "usage" in captured.err.lower() or "usage" in captured.out.lower()


def test_cli_backtest_help(capsys):
    """`backtest --help` exits 0 with usage info."""
    rc = cli.main(["backtest", "--help"])
    assert rc == 0
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "backtest" in combined.lower()


def test_cli_paper_trade_help(capsys):
    """`paper-trade --help` exits 0 with usage info."""
    rc = cli.main(["paper-trade", "--help"])
    assert rc == 0
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "paper-trade" in combined.lower()
