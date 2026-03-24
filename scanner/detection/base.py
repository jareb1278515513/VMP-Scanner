from __future__ import annotations

from abc import ABC, abstractmethod


class DetectionPlugin(ABC):
    """检测插件抽象基类。

    实现类需提供元数据、匹配、探测、验证和证据构造能力。
    """

    @abstractmethod
    def metadata(self) -> dict:
        """返回插件元信息。

        Returns:
            dict: 至少包含 ``name``、``category``、``title`` 等字段。
        """

        pass

    @abstractmethod
    def match(self, collection_bundle: dict, mode: str) -> bool:
        """判断插件是否适用于当前输入。

        Args:
            collection_bundle: 采集层输出。
            mode: 运行模式。

        Returns:
            bool: 适用返回 ``True``。
        """

        pass

    @abstractmethod
    def probe(self, collection_bundle: dict, mode: str) -> list[dict]:
        """生成候选漏洞项。

        Args:
            collection_bundle: 采集层输出。
            mode: 运行模式。

        Returns:
            list[dict]: 候选项列表。
        """

        pass

    @abstractmethod
    def verify(self, candidate: dict, collection_bundle: dict) -> bool:
        """对候选漏洞进行二次验证。

        Args:
            candidate: 候选漏洞。
            collection_bundle: 采集层输出。

        Returns:
            bool: 验证通过返回 ``True``。
        """

        pass

    @abstractmethod
    def evidence(self, candidate: dict) -> dict:
        """提取可落盘的证据字段。

        Args:
            candidate: 候选漏洞。

        Returns:
            dict: 证据字典。
        """

        pass
