"""Run the recording proxy: ``python -m keboola.vcr.proxy --mode replay --config tests/vcr.json``.

Record mode reaches the real APIs and writes sanitized cassettes. Replay mode never opens an upstream
connection: every answer comes from a cassette, and a request with no recorded match gets a clear error.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal

from .config import ProxyConfig


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="python -m keboola.vcr.proxy", description=__doc__)
    p.add_argument("--mode", choices=["record", "replay"], default=os.environ.get("VCR_MODE", "replay"))
    p.add_argument("--config", default=os.environ.get("VCR_CONFIG"), help="path to vcr.json (optional)")
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--listen-port", type=int, default=8080)
    p.add_argument("--control-port", type=int, default=8081)
    p.add_argument("--confdir", default=os.environ.get("VCR_CONFDIR", "~/.mitmproxy"), help="mitmproxy CA dir")
    return p.parse_args(argv)


async def _run(args: argparse.Namespace) -> None:
    from mitmproxy.options import Options
    from mitmproxy.tools.dump import DumpMaster

    from .addon import VcrProxyAddon

    config = ProxyConfig.load(args.config)
    opts = Options(listen_host=args.listen_host, listen_port=args.listen_port, confdir=args.confdir)
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.addons.add(VcrProxyAddon(args.mode, config, control_port=args.control_port))
    if args.mode == "replay":
        # Offline: no upstream connection for certificate sniffing or eager connects.
        master.options.update(upstream_cert=False, connection_strategy="lazy")
    master.options.update(termlog_verbosity="warn")
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, master.shutdown)
    await master.run()


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    logging.getLogger("mitmproxy").setLevel(logging.WARNING)  # per-connection lines are noise in test logs
    asyncio.run(_run(parse_args(argv)))


if __name__ == "__main__":
    main()
