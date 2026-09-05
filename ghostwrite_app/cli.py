from __future__ import annotations

import json
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .banner import GHOSTWRITE_BANNER
from .memory import TEMPLATES, run

console = Console()


def _banner() -> None:
    console.print(f"[bold white]{GHOSTWRITE_BANNER}[/bold white]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD memory poison tester — межсессионное отравление памяти агента."""


@main.command("templates")
def templates_cmd() -> None:
    for item in TEMPLATES:
        console.print(item)


@main.command("test")
@click.argument("url")
@click.option("--session-header", default="X-Session-Id", show_default=True,
              help="каким заголовком агент различает сессии")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-находку (контракт пайплайна)")
def test_cmd(url: str, session_header: str, as_json: str | None) -> None:
    """Полный тест: инъекция в сессии A → проверка в новой сессии B → контроль C."""
    d = run(url, session_header=session_header)
    if as_json:
        Path(as_json).write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")

    # 🔴 rc=2 «не состоялась» отделяем от rc=1 «не прошла»: несостоявшееся не выдаём за «чисто».
    if d["verdict"] == "НЕ ПРОВЕРЕНО":
        console.print(f"[yellow]НЕ ПРОВЕРЕНО[/yellow]: {d.get('not_proven', '')}")
        raise SystemExit(2)

    table = Table(title=f"ghostwrite: {url}")
    table.add_column("сессия"); table.add_column("канарейка")
    table.add_row("C (baseline, до инъекции)", "чисто")
    table.add_row("A (инъекция атакующего)", "принята" if d["инъекция_принята_A"] else "отклонена")
    table.add_row("B (новая сессия жертвы)", "🔴 всплыла" if d["всплыла_в_B"] else "не всплыла")
    console.print(table)
    цвет = {"ПРОВАЛ": "red", "ВНИМАНИЕ": "yellow"}.get(d["verdict"], "green")
    console.print(f"Вердикт: [{цвет}]{d['verdict']}[/{цвет}] — {d['почему']}")

    if d["verdict"] == "ПРОВАЛ":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
