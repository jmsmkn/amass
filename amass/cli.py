import asyncio
import json
import shutil
from functools import wraps
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, Callable, Dict

import aiohttp
import click
import tomlkit
from pkg_resources import get_distribution

from amass import generate_lock_file, parse_dependencies, parse_lock_file

CONCURRENT_REQUESTS = 5


def coroutine(f: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(f)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return asyncio.run(f(*args, **kwargs))

    return wrapper


def _get_settings() -> Dict[str, Path]:
    with open("pyproject.toml") as f:
        content = f.read()

    document = tomlkit.parse(content)

    return {
        "output_dir": Path(
            document.get("tool", {}).get("amass", {}).get("output", "vendor")
        )
    }


@click.group(context_settings=dict(help_option_names=["-h", "--help"]))
@click.version_option(get_distribution("amass").version, "-v", "--version")
def cli() -> None:
    pass


@cli.command(name="lock", short_help="Lock the dependencies")
@coroutine
async def lock() -> None:
    with open("pyproject.toml") as f:
        content = f.read()

    document = tomlkit.parse(content)

    dependencies = parse_dependencies(
        dependencies=document["tool"]["amass"]["dependencies"]
    )

    semaphore = asyncio.Semaphore(value=CONCURRENT_REQUESTS)
    async with aiohttp.ClientSession() as session:
        tasks = [
            dependency.update_assets(session=session, semaphore=semaphore)
            for dependency in dependencies
        ]
        await asyncio.gather(*tasks)

    lock_file = generate_lock_file(dependencies=dependencies)

    with open("amass.lock", "w") as f:
        f.write(json.dumps(lock_file.content, indent=2))
        f.write("\n")


@cli.command(
    name="install", short_help="Install the dependencies from the lock file"
)
@coroutine
async def install() -> None:

    with open("amass.lock") as f:
        content = json.loads(f.read())

    lock_file = parse_lock_file(content=content)

    with TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir) / "output"
        tmp_path.mkdir()

        semaphore = asyncio.Semaphore(value=CONCURRENT_REQUESTS)
        async with aiohttp.ClientSession() as session:
            await asyncio.gather(
                lock_file.download(
                    session=session, semaphore=semaphore, output_dir=tmp_path
                )
            )

        lock_file.check_integrity(directory=tmp_path)

        output_dir = _get_settings()["output_dir"]
        if output_dir.exists():
            shutil.rmtree(output_dir)

        output_dir.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.rename(output_dir)
