import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory

import aiohttp
import pytest
import pytest_asyncio
import tomlkit
from click.testing import CliRunner
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from amass import (
    AssetFile,
    Dependency,
    LockedDependency,
    LockFile,
    Provider,
    generate_lock_file,
    get_dependency_provider,
    parse_dependencies,
    parse_lock_file,
)
from amass.cli import CONCURRENT_REQUESTS, cli

TEST_VERSIONS = [
    "0.0.8",
    "0.1.0",
    "0.1.1",
    "0.1.2",
    "0.2.0",
    "0.3.0",
    "0.4.0",
    "0.4.1",
    "1.0.0",
    "1.0.1",
    "1.0.2",
    "1.1.0",
    "1.2.0",
    "1.2.1",
    "1.3.0",
    "1.3.1",
    "1.3.2",
    "1.3.3",
    "1.4.0",
    "1.4.1",
    "1.5.0",
    "1.6.0",
    "1.6.1",
    "1.7.0",
]
TEST_LOCK_FILE = {
    "content_hash": (
        "sha256:ad85f173abc4da1023762546637c542ad6c23ef14edf0ecdfb8751d589db9279"
    ),
    "dependencies": [
        {
            "assets": [
                {
                    "name": "htmx.min.js",
                    "sri": (
                        "sha512-etqA0KankuxrlSeZDYycQBY/D/KWZn0YZjlsjAo7kCEBTy1gg+DwmR6icxtOpqDBOzm2P00/lSIXEu7K+zvNsg=="
                    ),
                },
            ],
            "name": "htmx",
            "version": "1.7.0",
            "provider": "cdnjs",
        }
    ],
    "lock_version": "1.0",
}


def test_cli():
    runner = CliRunner()
    result = runner.invoke(cli)
    assert result.output != ""


@pytest_asyncio.fixture
async def session():
    async with aiohttp.ClientSession() as s:
        yield s


@pytest.fixture(scope="session")
def semaphore():
    return asyncio.Semaphore(value=CONCURRENT_REQUESTS)


async def test_update_all_assets(session, semaphore):
    dependency = Dependency(
        name="htmx",
        specifiers=SpecifierSet("==1.7.0"),
        include_filter={
            "htmx(.min)?.js",
        },
    )
    await dependency.update_assets(
        session=session,
        semaphore=semaphore,
    )
    assert dependency.resolved_version == Version("1.7.0")
    assert dependency.assets == [
        AssetFile(
            name="htmx.js",
            sri="sha512-wJXYT7RzKp/dxju83CCCATupp32GQvko0KrJVK3zTgTMkVWiLiHnupKKgOUt+87t+oe/Rm2Q2p+pOpiD+IR0lQ==",
        ),
        AssetFile(
            name="htmx.min.js",
            sri="sha512-etqA0KankuxrlSeZDYycQBY/D/KWZn0YZjlsjAo7kCEBTy1gg+DwmR6icxtOpqDBOzm2P00/lSIXEu7K+zvNsg==",
        ),
    ]


def test_resolve_dependency():
    dependency = Dependency(name="foo")
    assert dependency.resolve_version(
        versions={Version(v) for v in TEST_VERSIONS}
    ) == Version("1.7.0")


def test_dependency_to_lock_entry():
    dependency = Dependency(
        name="foo",
        resolved_version=Version("1.7.0"),
        assets=[],
        provider=Provider.CDNJS,
    )
    assert dependency.locked == LockedDependency(
        name="foo", version="1.7.0", assets=[], provider=Provider.CDNJS
    )


def test_lock_file_content():
    lock_file = LockFile(
        dependencies=[
            LockedDependency(
                name="foo", version="3.6.0", assets=[], provider=Provider.CDNJS
            )
        ]
    )
    assert lock_file.content == {
        "lock_version": "1.0",
        "content_hash": (
            "sha256:6fb6e863aa6e3358295c0fe699e63222134eff1e65c025763e3f7599e72e737f"
        ),
        "dependencies": [
            {
                "name": "foo",
                "version": "3.6.0",
                "assets": [],
                "provider": "cdnjs",
            }
        ],
    }


def test_parse_lock_file():
    content = {
        "lock_version": "1.0",
        "content_hash": (
            "sha256:6fb6e863aa6e3358295c0fe699e63222134eff1e65c025763e3f7599e72e737f"
        ),
        "dependencies": [
            {
                "name": "foo",
                "version": "3.6.0",
                "assets": [],
                "provider": "cdnjs",
            }
        ],
    }

    assert parse_lock_file(content=content) == LockFile(
        dependencies=[
            LockedDependency(
                name="foo", version="3.6.0", assets=[], provider=Provider.CDNJS
            )
        ]
    )


async def test_generate_lock_file(session, semaphore):
    dependency = Dependency(
        name="htmx",
        include_filter={"htmx.min.js"},
        specifiers=SpecifierSet("==1.7.0"),
    )
    await dependency.update_assets(
        session=session,
        semaphore=semaphore,
    )
    lock_file = generate_lock_file(dependencies=[dependency])

    assert lock_file.content == TEST_LOCK_FILE


async def test_fetch_asset_file(session, semaphore):
    dependency = Dependency(name="htmx")
    await dependency.update_assets(session=session, semaphore=semaphore)
    locked_dependency = dependency.locked

    with TemporaryDirectory() as dir:
        output_path = Path(dir)
        asset = locked_dependency.assets[0]
        await asset.download(
            session=session,
            semaphore=semaphore,
            output_dir=output_path,
            dependency_provider=get_dependency_provider(
                provider=dependency.provider
            ),
            dependency_name=dependency.name,
            dependency_version=dependency.resolved_version,
        )

        with open(output_path / dependency.name / asset.name) as f:
            content = f.read()

    assert content != ""


async def test_download_lock_file(session, semaphore, tmp_path):
    lock_file = parse_lock_file(content=TEST_LOCK_FILE)

    await lock_file.download(
        session=session, semaphore=semaphore, output_dir=tmp_path
    )

    assert [str(f.relative_to(tmp_path)) for f in tmp_path.rglob("*")] == [
        "htmx",
        "htmx/htmx.min.js",
    ]


def test_parse_dependencies():
    dependencies = tomlkit.table()
    dependencies.add(
        "htmx", {"version": "==1.7.0", "include": ["htmx.min.js"]}
    )

    parsed = parse_dependencies(dependencies=dependencies)

    assert parsed == [
        Dependency(
            name="htmx",
            specifiers=SpecifierSet("==1.7.0"),
            include_filter={"htmx.min.js"},
        )
    ]
