<!--
  Copyright 2026 Thomas Steiner
  SPDX-License-Identifier: Apache-2.0
-->

# TOTP Vault

An offline-capable PWA that generates two-factor codes, keeps its tokens
encrypted, and backs every change up to a private GitHub repository. Vanilla
JavaScript, no build step, no runtime dependencies.

## Data format

The vault is a [FIDO Credential Exchange Format][cxf] (CXF) 1.0 document: one
`Item` per token, with a `totp` credential, the website in `scope.urls`, and
creation and modification times. CXF has no place for two things the app needs,
so it adds two extensions, named the way CXF requires for exporter-defined
extensions:

- `tomayac.github.io/totp-vault-icon` on an item: `{ name, mediaType, data }`,
  the icon as Base64.
- `tomayac.github.io/totp-vault-deleted` on the account:
  `{ name, items: [{ id, deletedAt }] }`, so a deletion syncs between devices.

CXF requires importers to ignore extensions they don't know, so other importers
read the tokens and skip the rest.

On disk and on GitHub, the CXF document is encrypted as a [JSON Web
Encryption][jwe] (RFC 7516) in the flattened JSON serialization, with
`PBES2-HS512+A256KW` key wrapping (PBKDF2-HMAC-SHA512, 600,000 iterations) and
`A256GCM` content encryption. Labels and icons are encrypted along with the
secrets. Any JOSE library opens the file with the password; with
[jose](https://github.com/panva/jose), raise its iteration limit:

```js
const { plaintext } = await jose.flattenedDecrypt(
  vault,
  new TextEncoder().encode(password),
  { maxPBES2Count: 1_000_000 },
);
```

## Import and export

The app imports and exports these formats, and its first run accepts any of
them:

- **Encrypted vault**: the JWE file described above.
- **CXF**: the same document, unencrypted.
- **Bitwarden**: unencrypted Bitwarden JSON, with each token as a login item.
- **otpauth links**: one `otpauth://totp/` link per line, in the [Key URI
  Format][otpauth].

**Add** also scans QR codes with the camera, or from an image you choose, paste,
or drop. The scanner skips ultra-wide and telephoto lenses, which can't focus up
close, and remembers the camera you pick. It uses the built-in `BarcodeDetector`
where there is one, and the vendored jsQR elsewhere.

## GitHub backup

Under **Settings**, the app writes the encrypted vault to a file in a GitHub
repository after every change. It needs a [fine-grained personal access
token][pat] with access to only that repository and the permission **Contents:
Read and write**. The token is stored encrypted with the vault.

Before each upload, the app reads the backup and merges it with its own copy, so
several devices can share one backup: per token, the later edit wins, and a
deletion wins over earlier edits. On a new device, choose **Restore from
GitHub**.

Changing the password re-encrypts the vault, but earlier commits in the
repository keep the old password.

## Fingerprint unlock

Under **Settings**, the app can create a passkey on the device and use the
WebAuthn [PRF extension][prf]: after user verification, such as a fingerprint,
the passkey returns a secret that's fixed for it. The app derives an AES key
from that secret with HKDF and stores the vault's content key wrapped with it,
so unlocking needs the fingerprint and no stored password. The password keeps
working, and other devices need it. After a password change, the app wraps the
new key for the passkey, which asks for the fingerprint once.

With the laptop closed, the fingerprint reader is out of reach, so the password
comes first. With the window management permission, which a setting asks for,
the app follows the [Window Management API][wm]: while no screen with
`isInternal` is on, the lid is closed. Without the permission, the app remembers
how you last unlocked on each display setup, identified by the size and pixel
density of the screen and whether more than one is on.

## Icons

Each token can show an icon, stored with it so it works offline and travels with
backups. **Get icons** fetches favicons from [icon.horse][icon-horse], which
sends it the websites you use. Under **⋯**, you can set a token's website, fetch
its icon again, or choose your own image.

## Hosting

The app is a static site: serve the folder from any HTTPS origin, or from
`http://localhost`. All paths are relative, so a subpath works. Bump `CACHE` in
`sw.js` whenever you change a file, or installed copies keep the old version.

## Tests

```sh
npm test
```

[cxf]: https://fidoalliance.org/specs/cx/cxf-v1.0-ps-20250814.html
[jwe]: https://www.rfc-editor.org/rfc/rfc7516
[otpauth]: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
[pat]: https://github.com/settings/personal-access-tokens/new
[icon-horse]: https://icon.horse
[prf]: https://w3c.github.io/webauthn/#prf-extension
[wm]: https://w3c.github.io/window-management/
