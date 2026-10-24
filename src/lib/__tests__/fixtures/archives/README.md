Reference archives for the ZIP reader tests, made by independent tools rather
than by HELIOS's own code:

- `zipcrypto.zip` — Info-ZIP `zip -P 'Inv-2026!'` (traditional PKWARE encryption)
- `streamed.zip` — `cat invoice.vbs | zip -P 'stream-pw' out.zip -` (ZipCrypto
  with a data descriptor, so the password check byte comes from the time field)
- `aes128.zip`, `aes256.zip` — pyzipper, WinZip AES, password `infected`
- `plain.zip` — unencrypted

Members: `invoice.vbs` and `notes.log` (copies alongside), plus `filler.txt`
(random base64) in the encrypted ones. The `.vbs` is an inert test string.
