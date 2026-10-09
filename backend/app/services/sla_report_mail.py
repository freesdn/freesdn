# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded SMTP notice transport with conservative acceptance semantics."""

import asyncio
import smtplib
import ssl
from contextlib import suppress
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate

from app.services.notification import SMTPProvider, _validate_email_address

TOTAL_TIMEOUT_SECONDS = 35


@dataclass(frozen=True)
class MailOutcome:
    state: str
    error_code: str | None = None


def _refused(code: int) -> MailOutcome:
    return MailOutcome("retry" if 400 <= code < 500 else "failed", "smtp_refused")


def _send(provider: SMTPProvider, recipient: str, url: str, message_id: str) -> MailOutcome:
    server = None
    submitting = False
    try:
        if provider.use_tls is not True:
            return MailOutcome("failed", "verified_tls_required")
        sender = _validate_email_address(provider.from_email or "")
        recipient = _validate_email_address(recipient)
        message = EmailMessage()
        message["From"] = sender
        message["To"] = recipient
        message["Subject"] = "Your FreeSDN SLA report is ready"
        message["Message-ID"] = message_id
        message["Date"] = formatdate(localtime=False)
        # No report contents, resource names, credentials, attachments or bearer links.
        message.set_content(
            "A scheduled SLA report is available in FreeSDN. Sign in to view it:\n\n"
            + url
            + "\n\nAccess requires your current organization and site permissions.\n"
        )
        server = smtplib.SMTP(provider.host, provider.port, timeout=10)
        server.starttls(context=ssl.create_default_context())
        if provider.username and provider.password:
            server.login(provider.username, provider.password)
        submitting = True
        refused = server.send_message(message, from_addr=sender, to_addrs=[recipient])
        if refused:
            return _refused(next(iter(refused.values()))[0])
        return MailOutcome("accepted")
    except smtplib.SMTPRecipientsRefused as exc:
        return _refused(next(iter(exc.recipients.values()))[0])
    except smtplib.SMTPResponseException as exc:
        return _refused(exc.smtp_code)
    except ssl.SSLCertVerificationError:
        return MailOutcome("failed", "smtp_certificate_invalid")
    except (ValueError, smtplib.SMTPNotSupportedError):
        return MailOutcome("failed", "smtp_configuration_invalid")
    except Exception:
        # A lost acknowledgement after DATA can mean that mail was accepted.
        # Never put exception text (possibly credentials/addresses) in logs or DB.
        return MailOutcome("unknown" if submitting else "retry", "smtp_connection_interrupted")
    finally:
        if server is not None:
            # QUIT failure must not turn acknowledged DATA into a retry. Closing
            # locally also avoids another network wait after an accepted message.
            with suppress(OSError):
                server.close()


async def send_notice(
    provider: SMTPProvider, recipient: str, url: str, message_id: str
) -> MailOutcome:
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_send, provider, recipient, url, message_id),
            timeout=TOTAL_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        # Cancelling to_thread does not kill the SMTP thread. It may still send;
        # the durable record must therefore forbid another automatic attempt.
        return MailOutcome("unknown", "smtp_deadline_exceeded")
