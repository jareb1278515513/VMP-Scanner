from __future__ import annotations

from dataclasses import dataclass

from scanner.assessment.contracts import AssessmentRequest, RiskBundle, RiskItem


DEFAULT_WEIGHTS: dict[str, float] = {
    "impact": 1.0,
    "likelihood": 1.0,
    "confidence": 1.0,
    "exposure": 1.0,
}

SEVERITY_BASELINE: dict[str, tuple[int, int]] = {
    "critical": (5, 5),
    "high": (4, 4),
    "medium": (3, 3),
    "low": (2, 2),
    "info": (1, 1),
}

CATEGORY_BASELINE: dict[str, tuple[int, int]] = {
    "sqli": (5, 4),
    "xss": (4, 4),
    "csrf": (3, 3),
    "path_traversal": (4, 4),
    "weak-credential": (4, 3),
    "surface-anomaly": (2, 2),
}

RECOMMENDATION_TEMPLATES: dict[str, tuple[str, str]] = {
    "sqli": (
        "使用参数化查询并在服务端实施严格输入校验。",
        "对相同参数重复提交 SQL 注入 payload，页面不应出现错误回显或差异响应。",
    ),
    "xss": (
        "对输出进行上下文感知编码，并配置 CSP 限制脚本执行。",
        "提交相同 XSS payload，页面应只显示转义文本且脚本不执行。",
    ),
    "csrf": (
        "为关键操作加入一次性 CSRF Token，并校验来源与会话绑定。",
        "在缺失或伪造 Token 情况下重复提交请求，应被服务端拒绝。",
    ),
    "path_traversal": (
        "限制可访问路径并在服务端做目录白名单校验。",
        "访问同路径字典项时应返回 403 或 404，不应泄露敏感资源。",
    ),
    "weak-credential": (
        "启用强密码策略、登录限速与失败锁定机制。",
        "使用弱口令凭据重复登录尝试，应触发失败告警或锁定策略。",
    ),
    "surface-anomaly": (
        "收敛对外暴露接口并为异常端点添加访问控制。",
        "再次扫描异常端点时不应返回高价值信息或管理入口内容。",
    ),
}

FALLBACK_RECOMMENDATION = (
    "结合漏洞类别补充针对性修复措施，并在变更后执行复测。",
    "按原始证据中的请求重放验证，确认漏洞迹象消失。",
)


@dataclass
class _ScoringContext:
    """评分上下文数据。"""

    impact: int
    likelihood: int
    confidence: float
    exposure_weight: float


class AssessmentService:
    """风险评估服务。

    将检测发现转换为可排序的风险项并生成统计摘要。
    """

    schema_version = "1.0"

    def assess(self, request: AssessmentRequest | dict) -> dict:
        """执行风险评估。

        Args:
            request: 评估请求对象或等价字典。

        Returns:
            dict: 风险评估结果（risk bundle）。
        """

        normalized = _coerce_request(request)
        finding_bundle = normalized.findings

        errors = list(finding_bundle.get("errors") or [])
        risk_items: list[RiskItem] = []
        weights = _normalize_weights(normalized.weights)

        for finding in finding_bundle.get("findings", []):
            try:
                risk_items.append(_build_risk_item(finding, weights))
            except Exception as exc:
                finding_id = finding.get("id", "unknown") if isinstance(finding, dict) else "unknown"
                errors.append(f"risk_item_failed:{finding_id}:{exc}")

        risk_items.sort(key=lambda item: item.score, reverse=True)

        bundle = RiskBundle(
            schema_version=self.schema_version,
            target=finding_bundle.get("target", "unknown"),
            risk_items=risk_items,
            summary=_build_summary(risk_items),
            errors=errors,
        )
        return bundle.to_dict()


def _coerce_request(request: AssessmentRequest | dict) -> AssessmentRequest:
    """将输入转换为 ``AssessmentRequest``。

    Args:
        request: 原始请求。

    Returns:
        AssessmentRequest: 标准化请求对象。

    Raises:
        ValueError: 输入类型不合法或缺失必要字段时抛出。
    """

    if isinstance(request, AssessmentRequest):
        return request

    if not isinstance(request, dict):
        raise ValueError("AssessmentService.assess request must be AssessmentRequest or dict.")

    findings = request.get("findings")
    if not isinstance(findings, dict) or not findings:
        raise ValueError("Assessment request missing required field: findings")

    weights = request.get("weights") or {}
    metadata = request.get("metadata") or {}
    if not isinstance(weights, dict):
        raise ValueError("Assessment request field weights must be dict")
    if not isinstance(metadata, dict):
        raise ValueError("Assessment request field metadata must be dict")

    return AssessmentRequest(findings=findings, weights=weights, metadata=metadata)


def _normalize_weights(weights: dict) -> dict[str, float]:
    """归一化权重配置。"""

    normalized: dict[str, float] = dict(DEFAULT_WEIGHTS)
    for key in DEFAULT_WEIGHTS:
        if key in weights:
            normalized[key] = float(weights[key])
    return normalized


def _build_risk_item(finding: dict, weights: dict[str, float]) -> RiskItem:
    """将单条发现转换为风险项。"""

    if not isinstance(finding, dict):
        raise ValueError("finding item must be a dict")

    category = str(finding.get("category", "unknown")).strip().lower()
    severity_hint = str(finding.get("severity_hint", "medium")).strip().lower()

    impact, likelihood = _resolve_impact_likelihood(category, severity_hint)
    confidence = _clamp_float(finding.get("confidence", 0.5), low=0.1, high=1.0)
    exposure_weight = _derive_exposure_weight(finding.get("location") or {})

    scoring = _ScoringContext(
        impact=impact,
        likelihood=likelihood,
        confidence=confidence,
        exposure_weight=exposure_weight,
    )

    score = _calculate_score(scoring, weights)
    level = _resolve_level(score)
    recommendation, retest = RECOMMENDATION_TEMPLATES.get(category, FALLBACK_RECOMMENDATION)

    return RiskItem(
        finding_id=str(finding.get("id", "unknown")),
        plugin=str(finding.get("plugin", "unknown")),
        category=category,
        title=str(finding.get("title", "Untitled finding")),
        score=score,
        level=level,
        impact=impact,
        likelihood=likelihood,
        confidence=round(confidence, 3),
        exposure_weight=round(exposure_weight, 3),
        recommendation=recommendation,
        retest=retest,
        location=dict(finding.get("location") or {}),
        evidence=dict(finding.get("evidence") or {}),
    )


def _resolve_impact_likelihood(category: str, severity_hint: str) -> tuple[int, int]:
    """根据类别或严重度提示解析影响与可能性。"""

    base = CATEGORY_BASELINE.get(category)
    if base is not None:
        return base
    return SEVERITY_BASELINE.get(severity_hint, SEVERITY_BASELINE["medium"])


def _derive_exposure_weight(location: dict) -> float:
    """根据位置上下文估算暴露权重。"""

    url = str(location.get("url", "")).lower()
    param = str(location.get("param", "")).lower()

    if not url:
        return 0.9
    if "localhost" in url or "127.0.0.1" in url:
        return 0.8
    if any(keyword in url for keyword in ("login", "admin", "manage", "api")):
        return 1.2
    if param in {"password", "passwd", "token", "auth"}:
        return 1.2
    return 1.0


def _calculate_score(scoring: _ScoringContext, weights: dict[str, float]) -> float:
    """计算综合风险分数。"""

    score = (
        scoring.impact * weights["impact"]
        * scoring.likelihood * weights["likelihood"]
        * scoring.confidence * weights["confidence"]
        * scoring.exposure_weight * weights["exposure"]
    )
    return round(score, 2)


def _resolve_level(score: float) -> str:
    """根据分值映射风险等级。"""

    if score >= 16:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


def _build_summary(items: list[RiskItem]) -> dict:
    """聚合风险等级统计。"""

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in items:
        summary[item.level.lower()] += 1
    return summary


def _clamp_float(value: object, low: float, high: float) -> float:
    """将浮点值限制在给定区间内。"""

    parsed = float(value)
    if parsed < low:
        return low
    if parsed > high:
        return high
    return parsed
