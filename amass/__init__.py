import asyncio
import functools
import hashlib
import json
import re
from abc import ABC, abstractmethod
from base64 import b64encode
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Optional,
    Pattern,
    Set,
    Type,
    Union,
)
from warnings import warn

import aiohttp
import tomlkit
from bs4 import BeautifulSoup
from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version


class Provider(str, Enum):
    # Identifier must be the upper case of the value
    CDNJS = "cdnjs"
    UNPKG = "unpkg"


class DependencyProvider(ABC):
    @staticmethod
    @abstractmethod
    async def get_versions(
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        name: str,
    ) -> Iterable[str]:
        ...

    @staticmethod
    @abstractmethod
    async def get_assets(
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        name: str,
        version: Version,
    ) -> Iterable["AssetFile"]:
        ...

    @staticmethod
    @abstractmethod
    async def fetch_file(
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        name: str,
        dependency_name: str,
        dependency_version: Version,
    ) -> bytes:
        ...


class CDNJSDependencyProvider(DependencyProvider):
    @staticmethod
    async def get_versions(
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        name: str,
    ) -> Iterable[str]:
        async with semaphore:
            async with session.get(
                f"https://api.cdnjs.com/libraries/{name}"
            ) as response:
                metadata = await response.json()

        versions: Iterable[str] = metadata["versions"]

        return versions

    @staticmethod
    async def get_assets(
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        name: str,
        version: Version,
    ) -> Iterable["AssetFile"]:
        async with semaphore:
            async with session.get(
                f"https://api.cdnjs.com/libraries/{name}/{version}"
            ) as response:
                metadata = await response.json()

        return [
            AssetFile(name=name, sri=metadata["sri"].get(name))
            for name in metadata["files"]
        ]

    @staticmethod
    async def fetch_file(
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        name: str,
        dependency_name: str,
        dependency_version: Version,
    ) -> bytes:
        async with semaphore:
            async with session.get(
                f"https://cdnjs.cloudflare.com/ajax/libs/{dependency_name}/{dependency_version}/{name}"
            ) as request:
                content: bytes = await request.read()

        return content


class UNPKGDependencyProvider(DependencyProvider):
    @staticmethod
    async def get_versions(
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        name: str,
    ) -> Iterable[str]:
        async with semaphore:
            async with session.get(
                f"https://unpkg.com/browse/{name}/",
                allow_redirects=True,
            ) as response:
                page = await response.text()

        # Unpkg does not provide a versions API, so parse out the html response
        soup = BeautifulSoup(page, "html.parser")

        scripts = soup.find_all("script")
        prefix = "window.__DATA__ = "

        for script in scripts:
            if script.text.startswith(prefix):
                metadata = script.text.replace(prefix, "")
                versions: Iterable[str] = json.loads(metadata)[
                    "availableVersions"
                ]
                break
        else:
            raise RuntimeError("Window data not found")

        return versions

    @staticmethod
    async def get_assets(
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        name: str,
        version: Version,
    ) -> Iterable["AssetFile"]:
        async with semaphore:
            async with session.get(
                f"https://unpkg.com/{name}@{version}/?meta"
            ) as response:
                metadata = await response.json()

        assets = []

        def append_assets(data: Dict[str, Any]) -> None:
            for file in data["files"]:
                if file["type"] == "file":
                    assets.append(
                        AssetFile(
                            name=file["path"].lstrip("/"),
                            sri=file["integrity"],
                        )
                    )
                elif file["type"] == "directory":
                    append_assets(file)
                else:
                    raise RuntimeError(f"Unknown type: {file['type']}")

        append_assets(metadata)

        return assets

    @staticmethod
    async def fetch_file(
        *,
        session: aiohttp.ClientSession,
        semaphore: asyncio.Semaphore,
        name: str,
        dependency_name: str,
        dependency_version: Version,
    ) -> bytes:
        async with semaphore:
            async with session.get(
                f"https://unpkg.com/{dependency_name}@{dependency_version}/{name}"
            ) as request:
                content: bytes = await request.read()

        return content


def get_dependency_provider(*, provider: Provider) -> Type[DependencyProvider]:
    if provider == Provider.CDNJS:
        return CDNJSDependencyProvider
    elif provider == Provider.UNPKG:
        return UNPKGDependencyProvider
    else:
        raise RuntimeError(f"Invalid provider: {provider}")


@dataclass(frozen=True)
class ProviderVersion:
    remote_version: str

    def __post_init__(self) -> None:
        try:
            _ = self.parsed_version
        except InvalidVersion:
            raise

    @property
    def parsed_version(self) -> Version:
        return Version(self.remote_version)


@dataclass(frozen=True)
class AssetFile:
    name: str
    sri: Optional[str] = None

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
        dependency_provider: Type[DependencyProvider],
        dependency_name: str,
        dependency_version: Union[Version, str],
    ) -> None:
        content = await dependency_provider.fetch_file(
            session=session,
            semaphore=semaphore,
            name=self.name,
            dependency_name=dependency_name,
            dependency_version=dependency_version,
        )

        self.check_integrity(content=content)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            executor=None,
            func=functools.partial(
                self.save_asset,
                output=output_dir / dependency_name / self.name,
                content=content,
            ),
        )

    def save_asset(self, *, output: Path, content: bytes) -> None:
        output.parent.mkdir(exist_ok=True, parents=True)

        with output.open("wb") as f:
            f.write(content)


@dataclass()
class LockedDependency:
    name: str
    version: str
    provider: Provider
    assets: Iterable[AssetFile]
    maps: List[str]

    def __post_init__(self) -> None:
        # Handle nested serializer
        assets = []
        for a in self.assets:
            if not isinstance(a, AssetFile):
                assets.append(AssetFile(**a))
            else:
                assets.append(a)
        self.assets = sorted(assets, key=lambda a: a.name)


@dataclass(frozen=True)
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
                session=session,
                semaphore=semaphore,
                output_dir=output_dir,
                dependency_provider=get_dependency_provider(
                    provider=dependency.provider
                ),
                dependency_name=dependency.name,
                dependency_version=dependency.version,
            )
            for dependency in self.dependencies
            for asset in dependency.assets
        ]
        await asyncio.gather(*tasks)

    def check_integrity(self, *, directory: Path) -> None:
        generated_files = {f for f in directory.rglob("*") if f.is_file()}

        found_files = set()

        for dependency in self.dependencies:
            for asset in dependency.assets:
                file = directory / dependency.name / asset.name
                found_files.add(file)
                with open(file, "rb") as f:
                    content = f.read()
                    asset.check_integrity(content=content)

        if generated_files != found_files:
            raise RuntimeError("Sets of files do not match")

    def create_maps(self, *, directory: Path) -> None:
        for dependency in self.dependencies:
            for map in dependency.maps:
                file = directory / dependency.name / map
                file.parent.mkdir(exist_ok=True, parents=True)
                file.touch(exist_ok=False)


@dataclass
class Dependency:
    name: str
    provider: Provider
    specifiers: SpecifierSet = SpecifierSet("")
    include_filter: Optional[Set[Pattern[str]]] = None
    resolved_version: Optional[str] = None
    assets: Optional[Iterable[AssetFile]] = None
    maps: Optional[List[str]] = None

    def __post_init__(self) -> None:
        if self.include_filter is not None:
            self.include_filter = {re.compile(f) for f in self.include_filter}

    def resolve_version(self, *, versions: Set[ProviderVersion]) -> str:
        if not versions:
            raise RuntimeError(f"No assets found for {self.name}")

        desired_version = max(
            self.specifiers.filter(
                iterable=(v.parsed_version for v in versions)
            )
        )

        for v in versions:
            if v.parsed_version == desired_version:
                return v.remote_version

        raise RuntimeError(f"Version not determined for {self.name}")

    @property
    def locked(self) -> LockedDependency:
        if self.assets is None:
            raise RuntimeError(f"Assets are not set for {self.name}")

        if self.resolved_version is None:
            raise RuntimeError(f"The version is not set for {self.name}")

        return LockedDependency(
            name=self.name,
            version=self.resolved_version,
            provider=self.provider,
            assets=self.assets,
            maps=[] if self.maps is None else self.maps,
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
    ) -> Set[ProviderVersion]:
        remote_versions = await get_dependency_provider(
            provider=self.provider
        ).get_versions(session=session, semaphore=semaphore, name=self.name)

        versions = set()

        for remote_version in remote_versions:
            try:
                version = ProviderVersion(remote_version=remote_version)
            except InvalidVersion:
                warn(
                    f"Skipping invalid version {remote_version} for {self.name}"
                )
                continue

            versions.add(version)

        return versions

    async def _update_assets(
        self, *, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore
    ) -> None:
        assets = await get_dependency_provider(
            provider=self.provider
        ).get_assets(
            session=session,
            semaphore=semaphore,
            name=self.name,
            version=self.resolved_version,
        )

        if self.include_filter is not None:
            assets = [
                asset
                for asset in assets
                if any(fltr.match(asset.name) for fltr in self.include_filter)
            ]

        self.assets = assets


def parse_lock_file(*, content: Dict[str, Any]) -> LockFile:
    lock_file = LockFile(
        dependencies=[LockedDependency(**d) for d in content["dependencies"]]
    )

    if lock_file.content != content:
        raise ValueError(
            f"Lock files do not match: {lock_file.content['content_hash']}"
        )

    return lock_file


def generate_lock_file(*, dependencies: Iterable[Dependency]) -> LockFile:
    return LockFile(dependencies=[d.locked for d in dependencies])


async def parse_toml_file(*, content: str) -> LockFile:
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

    return lock_file


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

        provider = meta.get("provider", "cdnjs")

        maps = list(meta.get("maps", []))

        parsed.append(
            Dependency(
                name=name,
                specifiers=SpecifierSet(version),
                include_filter=include_filter,
                provider=Provider[provider.upper()],
                maps=maps,
            )
        )

    return parsed


CONCURRENT_REQUESTS = 5
