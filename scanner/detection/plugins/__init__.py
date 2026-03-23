"""Vulnerability detection plugins."""

from scanner.detection.plugins.csrf_missing_token_plugin import CsrfMissingTokenPlugin
from scanner.detection.plugins.suspicious_endpoint_plugin import SuspiciousEndpointPlugin


def load_default_plugins() -> list:
	return [
		SuspiciousEndpointPlugin(),
		CsrfMissingTokenPlugin(),
	]


__all__ = [
	"load_default_plugins",
	"SuspiciousEndpointPlugin",
	"CsrfMissingTokenPlugin",
]
