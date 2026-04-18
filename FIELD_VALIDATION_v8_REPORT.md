# FIELD_VALIDATION_v8_REPORT — VALIDATE-v8-1

Autonomous re-run of `strata ingest run --auto-unpack --auto`
against every entry in `~/Wolfmark/Test Material/` after SPRINTS_v8
shipped 21 new modern-evidence-source parsers (IoT / wearables /
gaming / drones / connected car / ChromeOS / encrypted messaging /
financial / rideshare / dating / AI-generated content).

## Run outcome

All 23 items completed with `exit=0`. Zero plugin failures across
506 plugin × image runs. No regression against the v7 baseline —
every new v8 parser is dormant on the current test material, so
the existing pipeline timing is unchanged.

## Coverage gap — what's missing from Test Material

Every v8 parser follows documented shapes from public DFIR research
but the test-material collection doesn't yet include imagery that
exercises the new surfaces. Acquisition punch list, grouped by
sprint:

### IoT (IOT-1..5)
- **Alexa** app extraction from an iPhone or Android phone paired
  to at least two Echo devices (interaction cache + device inventory
  SQLite).
- **Google Home** app extraction with a paired Nest thermostat + a
  Nest camera (Assistant My Activity + thermostat history + camera
  event logs).
- **Ring** app extraction from a phone with at least one Ring
  Doorbell + one Ring Stick-Up camera (event history JSON +
  subscription).
- **Smart TV** — Roku or SmartThings paired-app extraction
  (recent-activity JSON).
- **Smart lock** — August or Yale app extraction with a week's
  worth of lock/unlock events.

### Wearables (WEAR-1..3)
- **Fitbit** — FitbitMobile.sqlite from an iPhone or Pixel paired
  to any recent Sense / Charge / Inspire / Versa.
- **Garmin** — Garmin Connect extraction with at least one FIT
  file (Fenix / Forerunner / Instinct).
- **Apple Watch** — iOS extraction with HealthKit database from a
  watch that has recorded ECG, Blood Oxygen, and workout routes.
  A fall-detection event log is a bonus.

### Gaming (GAME-1..3)
- **PlayStation App** mobile extraction with trophy + message +
  friend history (PS4 or PS5 linked).
- **Xbox app** Windows %LOCALAPPDATA% + mobile extraction with at
  least one game clip.
- **Nintendo Switch Online + Parental Controls** app extractions
  on a phone with a linked Nintendo Account.

### Drones (DRONE-1, DRONE-2)
- **DJI Fly / DJI GO 4** flight log (.txt flavour, any recent DJI
  aircraft: Mini / Air / Mavic / Phantom series).
- **Autel Explorer** flight log (Autel EVO / Lite+).
- **Skydio** mobile flight log (Skydio 2+ / X2 / X10 / S2+).
- **Parrot FreeFlight** flight log (Anafi family).

### Automotive (AUTO-1)
- **Tesla app** extraction (paired Model 3 / Y / S / X) with at
  least 30 days of location-update polling + charge sessions.
- **FordPass / MyChevrolet / Toyota / Honda / Nissan** equivalents
  from any connected vehicle.

### ChromeOS (CHROMEOS-1)
- **Chromebook** stateful-partition extraction (enterprise or
  personal) — `/home/chronos/`, `/etc/cros-machine-id`,
  enrollment policy files.
- Bonus: a Chromebook with Crostini enabled so the Linux-VM path
  exercises ARBOR's Linux parsers.

### Encrypted messaging (CHAT-1)
- **Signal Desktop** folder (`%APPDATA%\Signal\`) with
  config.json + db.sqlite.
- **Telegram Desktop** `tdata/` folder.
- **WhatsApp Business** (distinct from consumer WhatsApp).
- **Threema / Element / Matrix** desktop installations.
- **Discord** desktop cache with voice-session history.

### Financial / Rideshare / Dating (FIN-1 / RIDE-1 / DATE-1)
- **Venmo / Cash App / Apple Pay / Google Pay** mobile extractions.
- **Robinhood** trade history.
- **Uber / Lyft / DoorDash / Airbnb** mobile extractions.
- **Tinder / Bumble / Hinge / Grindr** app data (a full extraction
  is ideal so age-stated cross-platform inconsistency detection
  can run end-to-end).

### AI content (AI-1)
- A folder of **AI-generated images** spanning the ten catalog
  tools (Stable Diffusion / Midjourney / DALL-E / ComfyUI /
  Automatic1111 / Leonardo.ai / Firefly / Flux / Ideogram /
  Runway). Include at least one PNG with embedded
  Stable-Diffusion `parameters` text chunk and one with a
  ComfyUI workflow JSON.
- A ChatGPT / Claude desktop-app installation with interaction
  history in the local cache.

## What worked without any new images

The v8 sprints add parser primitives — they don't change the
CLI/unpack/classify pipeline, so the per-image plugin-pass rate,
auto-unpack throughput, and classification accuracy are identical
to the v7 baseline:

| Metric | Value |
|--------|-------|
| Items | 23 |
| Exit=0 | 23 |
| Plugin failures | 0 |
| Full-matrix walltime | ~3 min 20 s |
| New tests added in v8 | +85 (3,489 → 3,574) |
| clippy --workspace --lib -D warnings | clean |
| zero `.unwrap()` / `unsafe{}` / `println!` introduced | verified |

## Completion status

- IOT-1 Alexa — shipped, images needed for live validation
- IOT-2 Google Home — shipped, images needed
- IOT-3 Ring Doorbell — shipped, images needed
- IOT-4 Smart TV — shipped, images needed
- IOT-5 Smart Locks — shipped, images needed
- WEAR-1 Fitbit — shipped, images needed
- WEAR-2 Garmin — shipped, images needed
- WEAR-3 Apple Watch deep — shipped, images needed
- GAME-1 PlayStation — shipped, images needed
- GAME-2 Xbox Live — shipped, images needed
- GAME-3 Nintendo — shipped, images needed
- DRONE-1 DJI — shipped, images needed
- DRONE-2 Autel / Skydio / Parrot — shipped, images needed
- AUTO-1 Connected car — shipped, images needed
- CHROMEOS-1 ChromeOS — shipped, images needed
- CHAT-1 Encrypted messaging metadata — shipped, images needed
- FIN-1 Financial apps — shipped, images needed
- RIDE-1 Rideshare + delivery — shipped, images needed
- DATE-1 Dating apps — shipped, images needed
- AI-1 AI-generated content detection — shipped, images needed
- VALIDATE-v8-1 — shipped (this document)

Workspace: 3,574 tests passing, clippy clean, zero
`.unwrap()` / `unsafe{}` / `println!` introduced, all 9
load-bearing tests preserved.
