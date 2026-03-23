"""Vulnerability detection plugins."""

from scanner.detection.plugins.csrf_missing_token_plugin import CsrfMissingTokenPlugin
from scanner.detection.plugins.sensitive_path_plugin import SensitivePathPlugin
from scanner.detection.plugins.sqli_plugin import SqlInjectionPlugin
from scanner.detection.plugins.suspicious_endpoint_plugin import SuspiciousEndpointPlugin
from scanner.detection.plugins.weak_password_policy_plugin import WeakPasswordPolicyPlugin
from scanner.detection.plugins.xss_plugin import ReflectedXssPlugin


def load_default_plugins() -> list:
	return [
		SuspiciousEndpointPlugin(),
		SqlInjectionPlugin(),
		ReflectedXssPlugin(),
		SensitivePathPlugin(),
		CsrfMissingTokenPlugin(),
		WeakPasswordPolicyPlugin(),
	]


__all__ = [
	"load_default_plugins",
	"SuspiciousEndpointPlugin",
	"SqlInjectionPlugin",
	"ReflectedXssPlugin",
	"SensitivePathPlugin",
	"CsrfMissingTokenPlugin",
	"WeakPasswordPolicyPlugin",
]
