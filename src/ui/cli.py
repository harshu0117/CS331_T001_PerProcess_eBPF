"""
Interactive CLI & Rich Terminal Dashboard for live network usage monitoring.
Includes fallback plain-text rendering if 'rich' is not installed.
"""
from typing import Any, Dict, List, Optional

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False
    Console = None  # type: ignore

from src.storage.models import ProcessBandwidthSummary


def format_bytes(num_bytes: float) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def format_rate(rate_bps: float) -> str:
    return f"{format_bytes(rate_bps)}/s"


def render_dashboard(
    summaries: List[ProcessBandwidthSummary],
    protocol_filter: str = "ALL",
    interval_sec: float = 1.0,
    sort_by: str = "total",
    console: Optional[Any] = None,
) -> None:
    total_upload_rate = 0.0
    total_download_rate = 0.0
    total_sent = 0
    total_recv = 0

    for s in summaries:
        total_upload_rate += s.send_rate_bps
        total_download_rate += s.recv_rate_bps
        total_sent += s.total_bytes_sent
        total_recv += s.total_bytes_recv

    if HAVE_RICH:
        if console is None:
            console = Console()

        table = Table(title="Live Process Network Bandwidth", expand=True)
        table.add_column("PID", style="cyan", justify="right", width=8)
        table.add_column("Process Name", style="bold white", width=16)
        table.add_column("Protocol", style="bold yellow", justify="center", width=10)
        table.add_column("Remote IP Address", style="bright_cyan", justify="left", min_width=20)
        table.add_column("Upload Rate", style="magenta", justify="right", width=13)
        table.add_column("Download Rate", style="green", justify="right", width=13)
        table.add_column("Total Sent", style="dim magenta", justify="right", width=11)
        table.add_column("Total Recv", style="dim green", justify="right", width=11)

        for s in summaries:
            table.add_row(
                str(s.pid),
                s.comm,
                s.protocol_label,
                s.remote_ips_str,
                format_rate(s.send_rate_bps),
                format_rate(s.recv_rate_bps),
                format_bytes(s.total_bytes_sent),
                format_bytes(s.total_bytes_recv),
            )

        # Summary footer row
        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{len(summaries)} processes[/bold]",
            protocol_filter,
            "-",
            f"[bold magenta]{format_rate(total_upload_rate)}[/bold magenta]",
            f"[bold green]{format_rate(total_download_rate)}[/bold green]",
            f"[bold]{format_bytes(total_sent)}[/bold]",
            f"[bold]{format_bytes(total_recv)}[/bold]",
        )

        summary_text = (
            f"[bold]Total Upload:[/bold] [magenta]{format_rate(total_upload_rate)}[/magenta] | "
            f"[bold]Total Download:[/bold] [green]{format_rate(total_download_rate)}[/green] | "
            f"[bold]Filter:[/bold] {protocol_filter} | "
            f"[bold]Sort:[/bold] {sort_by} | "
            f"[bold]Interval:[/bold] {interval_sec:.1f}s"
        )

        console.clear()
        console.print(Panel(summary_text, title="eBPF Network Usage Tracker", border_style="bright_blue"))
        console.print(table)
    else:
        # Standard library fallback
        print("\n" + "=" * 115)
        print(f"--- Live Network Usage (Filter: {protocol_filter}, Sort: {sort_by}, Interval: {interval_sec:.1f}s) ---")
        print(f"{'PID':>8} {'COMM':<16} {'PROTO':^10} {'REMOTE IP ADDRESS':<24} {'UPLOAD RATE':>13} {'DOWNLOAD RATE':>13} {'SENT':>10} {'RECV':>10}")
        print("-" * 115)
        for s in summaries:
            print(
                f"{s.pid:>8} {s.comm:<16} {s.protocol_label:^10} {s.remote_ips_str:<24} "
                f"{format_rate(s.send_rate_bps):>13} {format_rate(s.recv_rate_bps):>13} "
                f"{format_bytes(s.total_bytes_sent):>10} {format_bytes(s.total_bytes_recv):>10}"
            )
        print("-" * 115)
        print(
            f"{'TOTAL':>8} {f'{len(summaries)} procs':<16} {protocol_filter:^10} {'-':<24} "
            f"{format_rate(total_upload_rate):>13} {format_rate(total_download_rate):>13} "
            f"{format_bytes(total_sent):>10} {format_bytes(total_recv):>10}"
        )
        print("=" * 115 + "\n")


def render_historical_report(
    processes: List[Dict[str, Any]],
    time_window_hours: float = 1.0,
    console: Optional[Any] = None,
) -> None:
    """Renders a historical bandwidth usage report."""
    if HAVE_RICH:
        if console is None:
            console = Console()
        table = Table(title=f"Network Usage History (Past {time_window_hours:.1f}h)", expand=True)
        table.add_column("Process", style="bold white", width=20)
        table.add_column("PID", style="cyan", justify="right", width=8)
        table.add_column("Download", style="green", justify="right", width=14)
        table.add_column("Upload", style="magenta", justify="right", width=14)
        table.add_column("Total Bandwidth", style="bold yellow", justify="right", width=16)

        total_dl = 0
        total_ul = 0
        for p in processes:
            dl = p.get("total_recv", 0)
            ul = p.get("total_sent", 0)
            tot = p.get("total_bytes", dl + ul)
            total_dl += dl
            total_ul += ul
            table.add_row(
                p.get("comm", "unknown"),
                str(p.get("pid", "-")),
                format_bytes(dl),
                format_bytes(ul),
                format_bytes(tot),
            )

        table.add_section()
        table.add_row(
            "[bold]TOTAL[/bold]",
            "-",
            f"[bold green]{format_bytes(total_dl)}[/bold green]",
            f"[bold magenta]{format_bytes(total_ul)}[/bold magenta]",
            f"[bold yellow]{format_bytes(total_dl + total_ul)}[/bold yellow]",
        )
        console.print(table)
    else:
        print("\n" + "=" * 80)
        print(f"--- NETWORK USAGE HISTORY (Past {time_window_hours:.1f}h) ---")
        print(f"{'PROCESS':<20} {'PID':>8} {'DOWNLOAD':>14} {'UPLOAD':>14} {'TOTAL':>16}")
        print("-" * 80)
        total_dl = 0
        total_ul = 0
        for p in processes:
            dl = p.get("total_recv", 0)
            ul = p.get("total_sent", 0)
            tot = p.get("total_bytes", dl + ul)
            total_dl += dl
            total_ul += ul
            print(f"{p.get('comm', 'unknown'):<20} {str(p.get('pid', '-')):>8} {format_bytes(dl):>14} {format_bytes(ul):>14} {format_bytes(tot):>16}")
        print("-" * 80)
        print(f"{'TOTAL':<20} {'-':>8} {format_bytes(total_dl):>14} {format_bytes(total_ul):>14} {format_bytes(total_dl + total_ul):>16}")
        print("=" * 80 + "\n")


def render_top_consumers(
    processes: List[Dict[str, Any]],
    top_n: int = 10,
    console: Optional[Any] = None,
) -> None:
    """Renders top bandwidth consuming processes."""
    if HAVE_RICH:
        if console is None:
            console = Console()
        table = Table(title=f"Top {top_n} Network Consumers", expand=True)
        table.add_column("Rank", style="cyan", justify="right", width=6)
        table.add_column("Process Name", style="bold white", width=20)
        table.add_column("PID", style="cyan", justify="right", width=8)
        table.add_column("Total Bandwidth", style="bold yellow", justify="right", width=16)
        table.add_column("Upload", style="magenta", justify="right", width=14)
        table.add_column("Download", style="green", justify="right", width=14)

        for rank, p in enumerate(processes[:top_n], start=1):
            tot = p.get("total_bytes", 0)
            ul = p.get("total_sent", 0)
            dl = p.get("total_recv", 0)
            table.add_row(
                str(rank),
                p.get("comm", "unknown"),
                str(p.get("pid", "-")),
                format_bytes(tot),
                format_bytes(ul),
                format_bytes(dl),
            )
        console.print(table)
    else:
        print("\n" + "=" * 80)
        print(f"--- TOP {top_n} NETWORK CONSUMERS ---")
        print(f"{'RANK':>4} {'PROCESS':<20} {'PID':>8} {'TOTAL':>16} {'UPLOAD':>14} {'DOWNLOAD':>14}")
        print("-" * 80)
        for rank, p in enumerate(processes[:top_n], start=1):
            tot = p.get("total_bytes", 0)
            ul = p.get("total_sent", 0)
            dl = p.get("total_recv", 0)
            print(f"{rank:>4} {p.get('comm', 'unknown'):<20} {str(p.get('pid', '-')):>8} {format_bytes(tot):>16} {format_bytes(ul):>14} {format_bytes(dl):>14}")
        print("=" * 80 + "\n")
