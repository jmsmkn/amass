import asyncio
import functools
import hashlib
import json
import re
from base64 import b64encode
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Pattern, Set
from warnings import warn

import aiohttp
import tomlkit
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version


@dataclass
class AssetFile:
    name: str
    sri: Optional[str] = None

    @property
    def relative_path(self) -> Path:
        library, _, *filename = self.name.split("/")
        return Path(library, *filename)

    async def fetch(
        self,
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
    ) -> bytes:
        async with semaphore:
            async with session.get(
                f"https://cdnjs.cloudflare.com/ajax/libs/{self.name}"
            ) as request:
                content: bytes = await request.read()

        self.check_integrity(content=content)

        return content

    def check_integrity(self, *, content: bytes) -> None:
        if self.sri is not None:
            algorithm, hash_b64 = self.sri.split("-", 2)

            m = hashlib.new(algorithm)
            m.update(content)

            if b64encode(m.digest()).decode("utf-8") != hash_b64:
                raise RuntimeError(f"Hashes do not match for {self}")

    async def download(
        self,
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        output_dir: Path,
    ) -> None:
        content = await self.fetch(session=session, semaphore=semaphore)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            executor=None,
            func=functools.partial(
                self.save_asset,
                output_dir=output_dir,
                content=content,
            ),
        )

    def save_asset(self, *, output_dir: Path, content: bytes) -> None:
        output_file = output_dir / self.relative_path
        output_file.parent.mkdir(exist_ok=True, parents=True)

        with output_file.open("wb") as f:
            f.write(content)


@dataclass
class LockedDependency:
    name: str
    version: str
    assets: Iterable[AssetFile]

    def __post_init__(self) -> None:
        # Handle nested serializer
        assets = []
        for a in self.assets:
            if not isinstance(a, AssetFile):
                assets.append(AssetFile(**a))
            else:
                assets.append(a)
        self.assets = sorted(assets, key=lambda a: a.name)


@dataclass
class LockFile:
    dependencies: Iterable[LockedDependency]

    @property
    def metadata(self) -> Dict[str, str]:
        return {
            "version": "1.0",
            "algorithm": "sha256",
        }

    @property
    def content(self) -> Dict[str, Any]:
        dependencies = [
            asdict(d) for d in sorted(self.dependencies, key=lambda d: d.name)
        ]

        m = hashlib.new(name=self.metadata["algorithm"])
        m.update(json.dumps(dependencies).encode("utf-8"))

        return {
            "lock_version": self.metadata["version"],
            "content_hash": f"{m.name}:{m.hexdigest()}",
            "dependencies": dependencies,
        }

    async def download(
        self,
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        output_dir: Path,
    ) -> None:
        tasks = [
            asset.download(
                session=session, semaphore=semaphore, output_dir=output_dir
            )
            for dependency in self.dependencies
            for asset in dependency.assets
        ]
        await asyncio.gather(*tasks)

    def check_integrity(self, *, directory: Path) -> None:
        expected_assets = [
            asset
            for dependency in self.dependencies
            for asset in dependency.assets
        ]
        generated_files = {f for f in directory.rglob("*") if f.is_file()}

        if {f.relative_to(directory) for f in generated_files} != {
            a.relative_path for a in expected_assets
        }:
            raise RuntimeError("Sets of files do not match")

        for asset in expected_assets:
            with open(directory / asset.relative_path, "rb") as f:
                content = f.read()
                asset.check_integrity(content=content)


@dataclass
class Dependency:
    name: str
    specifiers: SpecifierSet = SpecifierSet("")
    include_filter: Optional[Set[Pattern[str]]] = None
    resolved_version: Optional[Version] = None
    assets: Optional[Iterable[AssetFile]] = None

    def __post_init__(self) -> None:
        if self.include_filter is not None:
            self.include_filter = {re.compile(f) for f in self.include_filter}

    def resolve_version(self, *, versions: Set[Version]) -> Version:
        if not versions:
            raise RuntimeError(f"No assets found for {self.name}")

        return max(self.specifiers.filter(iterable=versions))

    @property
    def locked(self) -> LockedDependency:
        if self.assets is None:
            raise RuntimeError(f"Assets are not set for {self.name}")

        if self.resolved_version is None:
            raise RuntimeError(f"The version is not set for {self.name}")

        return LockedDependency(
            name=self.name,
            version=str(self.resolved_version),
            assets=self.assets,
        )

    async def update_assets(
        self, *, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore
    ) -> None:
        versions = await self._find_versions(
            session=session, semaphore=semaphore
        )
        self.resolved_version = self.resolve_version(versions=versions)
        await self._update_assets(session=session, semaphore=semaphore)

    async def _find_versions(
        self, *, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore
    ) -> Set[Version]:
        async with semaphore:
            async with session.get(
                f"https://api.cdnjs.com/libraries/{self.name}"
            ) as response:
                metadata = await response.json()

                versions = set()

                for version_str in metadata["versions"]:
                    try:
                        version = Version(version_str)
                    except InvalidVersion:
                        warn(
                            f"Skipping invalid version {version_str} for {self.name}"
                        )
                        continue

                    versions.add(version)

                return versions

    async def _update_assets(
        self, *, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore
    ) -> None:
        async with semaphore:
            async with session.get(
                f"https://api.cdnjs.com/libraries/{self.name}/{self.resolved_version}"
            ) as response:
                metadata = await response.json()

                if self.include_filter is not None:
                    filenames = [
                        filename
                        for filename in metadata["files"]
                        if any(
                            filter.match(filename)
                            for filter in self.include_filter
                        )
                    ]
                else:
                    filenames = metadata["files"]

                self.assets = [
                    AssetFile(
                        name=f"{self.name}/{self.resolved_version}/{filename}",
                        sri=metadata["sri"].get(filename),
                    )
                    for filename in filenames
                ]


def parse_lock_file(*, content: Dict[str, Any]) -> LockFile:
    lock_file = LockFile(
        dependencies=[LockedDependency(**d) for d in content["dependencies"]]
    )

    if lock_file.content != content:
        raise ValueError("Lock files do not match")

    return lock_file


def generate_lock_file(*, dependencies: Iterable[Dependency]) -> LockFile:
    return LockFile(dependencies=[d.locked for d in dependencies])


def parse_dependencies(
    *, dependencies: tomlkit.items.Table
) -> Iterable[Dependency]:
    parsed = []

    for name, meta in dependencies.items():
        include = meta.get("include")

        if include is not None:
            include_filter = {*include}
        else:
            include_filter = None

        version = meta.get("version")

        if version == "*":
            version = ""

        parsed.append(
            Dependency(
                name=name,
                specifiers=SpecifierSet(version),
                include_filter=include_filter,
            )
        )

    return parsed
