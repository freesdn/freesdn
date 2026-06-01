# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2024-2026 FreeSDN
"""
FreeSDN - Internationalization (i18n) Service
===================================================

Multi-language support with lazy loading and locale detection.

Features:
- Language detection from Accept-Language header
- User preference override
- Lazy-loaded translations
- Pluralization support
- Date/time/number formatting
- Translation extraction support

Supported Languages:
- English (en) - Default
- French (fr)
- Spanish (es)
- German (de)
- Portuguese (pt-BR)
- Chinese (zh)
- Arabic (ar) - RTL
- Hebrew (he) - RTL

Usage:
    from app.core.i18n import get_translator, _

    # In FastAPI endpoint
    t = get_translator(request)
    message = t("error.not_found")

    # Or with current request context
    message = _("error.not_found")
"""

import json
import logging
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from babel import Locale, dates, numbers

logger = logging.getLogger(__name__)


# =============================================================================
# Constants
# =============================================================================

# Supported locales
SUPPORTED_LOCALES = [
    "en",  # English (default)
    "fr",  # French
    "es",  # Spanish
    "de",  # German
    "pt-BR",  # Portuguese (Brazil)
    "zh",  # Chinese
    "ar",  # Arabic (RTL)
    "he",  # Hebrew (RTL)
]

DEFAULT_LOCALE = "en"

# RTL languages
RTL_LOCALES = {"ar", "he", "fa", "ur"}

# Locale directory
LOCALE_DIR = Path(__file__).parent.parent / "locales"


# =============================================================================
# Context Variables
# =============================================================================

# Current request locale context
_current_locale: ContextVar[str] = ContextVar("current_locale", default=DEFAULT_LOCALE)


# =============================================================================
# Locale Detection
# =============================================================================


def parse_accept_language(header: str) -> list[tuple[str, float]]:
    """
    Parse Accept-Language header into list of (locale, quality) tuples.

    Example: "fr-FR,fr;q=0.9,en;q=0.8" -> [("fr-FR", 1.0), ("fr", 0.9), ("en", 0.8)]
    """
    if not header:
        return []

    locales = []
    for part in header.split(","):
        part = part.strip()
        if not part:
            continue

        if ";q=" in part:
            locale, q = part.split(";q=", 1)
            try:
                quality = float(q)
            except ValueError:
                quality = 1.0
        else:
            locale = part
            quality = 1.0

        locales.append((locale.strip(), quality))

    # Sort by quality descending
    locales.sort(key=lambda x: x[1], reverse=True)
    return locales


def normalize_locale(locale: str) -> str:
    """Normalize locale string to match supported locales."""
    if not locale:
        return DEFAULT_LOCALE

    # Direct match
    if locale in SUPPORTED_LOCALES:
        return locale

    # Try lowercased
    locale_lower = locale.lower()
    for supported in SUPPORTED_LOCALES:
        if supported.lower() == locale_lower:
            return supported

    # Try language code only (e.g., "en-US" -> "en")
    lang_code = locale.split("-")[0].split("_")[0].lower()
    for supported in SUPPORTED_LOCALES:
        if supported.lower().startswith(lang_code):
            return supported

    return DEFAULT_LOCALE


def detect_locale(
    accept_language: str | None = None,
    user_preference: str | None = None,
    query_param: str | None = None,
) -> str:
    """
    Detect the best locale for the request.

    Priority:
    1. Query parameter (lang=xx)
    2. User preference from DB
    3. Accept-Language header
    4. Default locale
    """
    # 1. Query parameter
    if query_param:
        normalized = normalize_locale(query_param)
        if normalized != DEFAULT_LOCALE or query_param.startswith("en"):
            return normalized

    # 2. User preference
    if user_preference:
        normalized = normalize_locale(user_preference)
        if normalized != DEFAULT_LOCALE or user_preference.startswith("en"):
            return normalized

    # 3. Accept-Language header
    if accept_language:
        for locale, _ in parse_accept_language(accept_language):
            normalized = normalize_locale(locale)
            if normalized in SUPPORTED_LOCALES:
                return normalized

    # 4. Default
    return DEFAULT_LOCALE


# =============================================================================
# Translation Loading
# =============================================================================


@lru_cache(maxsize=10)
def load_translations(locale: str) -> dict[str, Any]:
    """
    Load translations for a locale from JSON files.

    Cached per locale for performance.
    """
    locale = normalize_locale(locale)
    locale_path = LOCALE_DIR / locale

    translations: dict[str, Any] = {}

    if not locale_path.exists():
        if locale != DEFAULT_LOCALE:
            logger.warning("Locale directory not found: %s", locale_path)
        return translations

    # Load all JSON files in the locale directory
    for json_file in locale_path.glob("*.json"):
        try:
            with open(json_file, encoding="utf-8") as f:
                data = json.load(f)
                # Use filename (without .json) as namespace
                namespace = json_file.stem
                translations[namespace] = data
        except Exception as e:
            logger.error("Failed to load translation file %s: %s", json_file, e)

    return translations


def get_nested_value(data: dict[str, Any], key: str, default: str | None = None) -> str | None:
    """Get nested value from dict using dot notation."""
    keys = key.split(".")
    value: Any = data

    for k in keys:
        if isinstance(value, dict):
            value = value.get(k)
            if value is None:
                return default
        else:
            return default

    return str(value) if value is not None else default


# =============================================================================
# Translator Class
# =============================================================================


class Translator:
    """
    Translator for a specific locale.

    Usage:
        t = Translator("fr")
        message = t("common.welcome", name="John")
    """

    def __init__(self, locale: str):
        self.locale_code = normalize_locale(locale)
        self._translations = load_translations(self.locale_code)
        self._fallback = (
            load_translations(DEFAULT_LOCALE) if self.locale_code != DEFAULT_LOCALE else {}
        )

        try:
            self.babel_locale = Locale.parse(self.locale_code.replace("-", "_"))
        except (ValueError, TypeError):
            self.babel_locale = Locale.parse(DEFAULT_LOCALE)

    @property
    def is_rtl(self) -> bool:
        """Check if locale is RTL."""
        return self.locale_code in RTL_LOCALES

    def __call__(
        self,
        key: str,
        default: str | None = None,
        **kwargs: Any,
    ) -> str:
        """
        Translate a key with optional interpolation.

        Args:
            key: Translation key (e.g., "common.welcome" or "errors.not_found")
            default: Default value if key not found
            **kwargs: Variables for interpolation

        Returns:
            Translated string or key if not found
        """
        # Try to find in current locale
        value = None

        # Try with namespace prefix
        if "." in key:
            parts = key.split(".", 1)
            namespace = parts[0]
            rest = parts[1]

            if namespace in self._translations:
                value = get_nested_value(self._translations[namespace], rest)

        # Try flat key across all namespaces
        if value is None:
            for ns_data in self._translations.values():
                value = get_nested_value(ns_data, key)
                if value:
                    break

        # Fallback to default locale
        if value is None and self._fallback:
            if "." in key:
                parts = key.split(".", 1)
                namespace = parts[0]
                rest = parts[1]

                if namespace in self._fallback:
                    value = get_nested_value(self._fallback[namespace], rest)

            if value is None:
                for ns_data in self._fallback.values():
                    value = get_nested_value(ns_data, key)
                    if value:
                        break

        # Use default or key
        if value is None:
            value = default or key

        # Interpolate variables
        if kwargs:
            try:
                value = value.format(**kwargs)
            except KeyError as e:
                logger.warning("Missing interpolation variable in '%s': %s", key, e)

        return value

    def t(self, key: str, default: str | None = None, **kwargs: Any) -> str:
        """Alias for __call__."""
        return self(key, default, **kwargs)

    def plural(
        self,
        key: str,
        count: int,
        **kwargs: Any,
    ) -> str:
        """
        Get pluralized translation.

        Expects keys like:
        - key.zero
        - key.one
        - key.few (for some languages)
        - key.many
        - key.other
        """
        # Determine plural form
        if count == 0:
            plural_key = f"{key}.zero"
        elif count == 1:
            plural_key = f"{key}.one"
        elif count < 5:
            plural_key = f"{key}.few"
        else:
            plural_key = f"{key}.many"

        # Try specific form, fallback to 'other'
        result = self(plural_key, default=None, count=count, **kwargs)
        if result == plural_key:
            result = self(f"{key}.other", default=key, count=count, **kwargs)

        return result

    def format_number(self, number: int | float, decimal_places: int = 2) -> str:
        """Format number according to locale."""
        if isinstance(number, float):
            return str(
                numbers.format_decimal(
                    number, format=f"#,##0.{'0' * decimal_places}", locale=self.babel_locale
                )
            )
        return str(numbers.format_decimal(number, locale=self.babel_locale))

    def format_currency(self, amount: float, currency: str = "USD") -> str:
        """Format currency according to locale."""
        return str(numbers.format_currency(amount, currency, locale=self.babel_locale))

    def format_date(self, dt: datetime, format: str = "medium") -> str:
        """Format date according to locale."""
        return str(dates.format_date(dt, format=format, locale=self.babel_locale))

    def format_datetime(self, dt: datetime, format: str = "medium") -> str:
        """Format datetime according to locale."""
        return str(dates.format_datetime(dt, format=format, locale=self.babel_locale))

    def format_time(self, dt: datetime, format: str = "short") -> str:
        """Format time according to locale."""
        return str(dates.format_time(dt, format=format, locale=self.babel_locale))

    def format_relative_time(self, dt: datetime) -> str:
        """Format relative time (e.g., '2 hours ago')."""
        return str(
            dates.format_timedelta(
                datetime.now(UTC) - dt, locale=self.babel_locale, add_direction=True
            )
        )


# =============================================================================
# FastAPI Integration
# =============================================================================


def set_locale(locale: str) -> None:
    """Set the current request locale."""
    _current_locale.set(normalize_locale(locale))


def get_locale() -> str:
    """Get the current request locale."""
    return _current_locale.get()


def get_translator(locale: str | None = None) -> Translator:
    """
    Get a translator for the specified or current locale.

    Args:
        locale: Locale code, or None to use current context

    Returns:
        Translator instance
    """
    if locale is None:
        locale = get_locale()
    return Translator(locale)


def _(key: str, default: str | None = None, **kwargs: Any) -> str:
    """
    Shorthand translation function using current locale.

    Usage:
        from app.core.i18n import _
        message = _("errors.not_found")
    """
    return get_translator()(key, default, **kwargs)


# =============================================================================
# FastAPI Middleware
# =============================================================================


class LocaleMiddleware:
    """
    Middleware to detect and set locale for each request.

    Usage:
        from app.core.i18n import LocaleMiddleware
        app.add_middleware(LocaleMiddleware)
    """

    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))

            # Get Accept-Language header
            accept_language = headers.get(b"accept-language", b"").decode("utf-8", errors="ignore")

            # Get lang query parameter
            query_string = scope.get("query_string", b"").decode("utf-8")
            query_param = None
            for param in query_string.split("&"):
                if param.startswith("lang="):
                    query_param = param.split("=", 1)[1]
                    break

            # Detect and set locale
            locale = detect_locale(
                accept_language=accept_language,
                query_param=query_param,
            )
            set_locale(locale)

        await self.app(scope, receive, send)


# =============================================================================
# Translation Extraction Helper
# =============================================================================


def extract_translation_keys(directory: Path) -> set[str]:
    """
    Extract all translation keys from Python files.

    Looks for patterns like:
    - _("key")
    - t("key")
    - translator("key")
    """
    import re

    keys: set[str] = set()
    pattern = re.compile(r'[_t]\(\s*["\']([^"\']+)["\']')

    for py_file in directory.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8")
            matches = pattern.findall(content)
            keys.update(matches)
        except (OSError, UnicodeDecodeError):
            continue

    return keys


# =============================================================================
# Locale Info
# =============================================================================


def get_supported_locales() -> list[dict[str, Any]]:
    """Get list of supported locales with metadata."""
    return [
        {"code": "en", "name": "English", "native_name": "English", "rtl": False},
        {"code": "fr", "name": "French", "native_name": "Français", "rtl": False},
        {"code": "es", "name": "Spanish", "native_name": "Español", "rtl": False},
        {"code": "de", "name": "German", "native_name": "Deutsch", "rtl": False},
        {
            "code": "pt-BR",
            "name": "Portuguese (Brazil)",
            "native_name": "Português (Brasil)",
            "rtl": False,
        },
        {"code": "zh", "name": "Chinese", "native_name": "中文", "rtl": False},
        {"code": "ar", "name": "Arabic", "native_name": "العربية", "rtl": True},
        {"code": "he", "name": "Hebrew", "native_name": "עברית", "rtl": True},
    ]
