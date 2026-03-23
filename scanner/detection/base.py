from __future__ import annotations

from abc import ABC, abstractmethod


class DetectionPlugin(ABC):
    @abstractmethod
    def metadata(self) -> dict:
        pass

    @abstractmethod
    def match(self, collection_bundle: dict, mode: str) -> bool:
        pass

    @abstractmethod
    def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
        pass

    @abstractmethod
    def verify(self, candidate: dict, collection_bundle: dict) -> bool:
        pass

    @abstractmethod
    def evidence(self, candidate: dict) -> dict:
        pass
