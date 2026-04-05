from __future__ import annotations

import unittest
from email.message import EmailMessage

from app.services.eml_parser import parse_eml


class EmlParserTests(unittest.TestCase):
    def test_parse_eml_extracts_attachments(self):
        message = EmailMessage()
        message["Subject"] = "Attachment test"
        message["From"] = "alerts@example.com"
        message["To"] = "analyst@example.com"
        message["Message-ID"] = "<attachment-test@example.com>"
        message.set_content("Please review the attached file.")
        message.add_attachment(
            b"hello world",
            maintype="application",
            subtype="octet-stream",
            filename="payload.bin",
        )

        parsed_report, parsed_attachments = parse_eml(message.as_bytes())

        self.assertEqual(parsed_report["subject"], "Attachment test")
        self.assertEqual(len(parsed_attachments), 1)
        self.assertEqual(parsed_attachments[0].filename, "payload.bin")
        self.assertEqual(parsed_attachments[0].content_type, "application/octet-stream")
        self.assertEqual(parsed_attachments[0].data, b"hello world")


if __name__ == "__main__":
    unittest.main()
