Image fixtures for the OCR / QR tests, made with Python (qrcode + Pillow,
DejaVu Sans) rather than HELIOS's own code:

- `qr-lure.png` — a QR code for `https://login-microsoft365-secure.example.xyz/owa/?u=jdoe`
- `text-lure.jpg` — "Your mailbox password expires today. / Verify your account at /
  https://mail-verify.example.top/login" rendered as a picture

Both domains are illustrative lookalikes; the tests never contact them.
