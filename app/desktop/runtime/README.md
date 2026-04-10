# Embedded Desktop Runtime

This directory is the packaging source for the TapChat desktop app's embedded
Cloudflare deploy runtime.

- `dist/<platform>/node` contains the private Node runtime copied from the
  release machine.
- `dist/<platform>/cloudflare-service` contains the deployable
  `services/cloudflare` workspace and its runtime dependencies.

Populate `dist/<platform>` with:

```powershell
cd D:\Code\TapChat\app\desktop
npm run prepare:desktop-runtime
```
