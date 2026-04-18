# SPRINTS_v8.md — STRATA MODERN EVIDENCE SOURCES
# Drop this file in ~/Wolfmark/strata/ alongside CLAUDE.md
# Usage: "Read CLAUDE.md and SPRINTS_v8.md. Execute all incomplete sprints in order.
#         For each sprint: implement, test, commit, then move to the next."
# Last updated: 2026-04-17
# Prerequisite: SPRINTS.md through SPRINTS_v7.md complete
# Focus: Modern evidence sources that competitors underserve
#
# Context: Real casework in 2026+ increasingly involves non-traditional devices:
#   - IoT / smart home ecosystems (Alexa, Ring, Nest)
#   - Wearables (Fitbit, Garmin, Apple Watch deep)
#   - Gaming consoles (PlayStation, Xbox, Nintendo)
#   - Drones (DJI flight logs)
#   - Automotive (infotainment, event data recorders)
#   - ChromeOS
#   - Financial apps, dating apps, ride-share apps
#   - Deep encrypted messaging
#   - AI-generated content detection
#
# This sprint queue is 3 categories of modern evidence that Cellebrite
# and Magnet charge premium for but underdeliver. Strata can dominate here.

---

## HOW TO EXECUTE

Read CLAUDE.md first. Then execute each sprint below in order.
For each sprint:
1. Implement exactly as specified
2. Run `cargo test --workspace` — all tests must pass
3. Run `cargo clippy --workspace -- -D warnings` — must be clean
4. Verify zero `.unwrap()`, zero `unsafe{}`, zero `println!`
5. Commit with message: "feat: [sprint-id] [description]" or "fix: [sprint-id] [description]"
6. Move to next sprint immediately

---

## COMPLETED SPRINTS (skip these)

None yet — this is v8.

---

# ═══════════════════════════════════════════════════════
# PART 1 — IoT / SMART HOME ECOSYSTEM
# ═══════════════════════════════════════════════════════

## SPRINT IOT-1 — Amazon Alexa Ecosystem Artifacts

Create `plugins/strata-plugin-nimbus/src/alexa.rs` — extending Nimbus
for cloud-synced home automation evidence parsed from device artifacts.

**Problem statement:**
Alexa devices are in tens of millions of homes. They capture voice
commands, store interaction history, and can reveal:
- Who was home when (voice ID recognition)
- What was said (voice transcripts)
- Timeline of activity (smart home commands)
- External events (Ring notifications, doorbell presses)

Alexa data exists on paired phones and PCs. No air-gap tool parses
this well today.

**Implementation:**

**Alexa mobile app artifacts (iOS + Android):**

iOS location: `/private/var/mobile/Containers/Data/Application/{GUID}/`
where container is `com.amazon.echo`
- `Library/Preferences/com.amazon.echo.plist` — settings, account info
- `Library/Caches/com.amazon.echo/` — cached responses, recent interactions
- `Documents/` — local conversation history if enabled

Android location: `/data/data/com.amazon.dee.app/`
- `databases/` — SQLite databases with interaction metadata
- `shared_prefs/` — account and device preferences
- `files/` — cached audio transcriptions, device list

**Parse:**
```rust
pub struct AlexaArtifact {
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub device_name: Option<String>,       // "Kitchen Echo", "Bedroom Dot"
    pub device_type: Option<String>,       // Echo/Dot/Show/Plus
    pub utterance_text: Option<String>,    // What was said
    pub response_text: Option<String>,     // What Alexa said
    pub audio_reference: Option<String>,   // Reference to audio file if preserved
    pub user_speaker: Option<String>,      // Voice ID if recognized
    pub device_location: Option<String>,   // Room assignment
    pub account_email: Option<String>,
}
```

**Paired device inventory:**
Parse list of devices linked to the account:
- Echo devices (audio)
- Fire TV devices (viewing history)
- Ring devices (motion/doorbell)
- Smart plugs, bulbs, thermostats
- Third-party Alexa-compatible devices

**Skills enabled:**
List of third-party Alexa skills enabled on the account:
- May reveal interests, activities
- Shopping skills reveal financial behavior
- Fitness/mental health skills reveal personal data

**Timeline reconstruction:**
Alexa interaction history is one of the most detailed timelines available:
- Every voice command timestamped
- Smart home state changes timestamped
- Who said what (with voice ID)

**Forensic significance:**
- Alibi verification (was user home?)
- Intent evidence (what did user ask?)
- Timeline reconstruction
- Multiple occupant identification via voice ID

Emit `Artifact::new("Alexa Interaction", path_str)`.
Emit `Artifact::new("Alexa Device Inventory", path_str)`.
MITRE: T1005, T1430 (location tracking via home presence).
forensic_value: High — voice ID evidence is court-tested.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT IOT-2 — Google Home / Nest Ecosystem

Create `plugins/strata-plugin-carbon/src/google_home.rs`.

**Problem statement:**
Google Home / Nest ecosystem parallels Alexa. Different app, different
artifact paths, but similar evidentiary value.

**Implementation:**

**Google Home app artifacts:**

iOS: `/private/var/mobile/Containers/Data/Application/{GUID}/` where
container is `com.google.Chromecast` or `com.google.HomeFoundation.iOS.App`
- Similar structure to Alexa

Android: `/data/data/com.google.android.apps.chromecast.app/`
- `databases/home_graph.db` or similar — device topology
- `shared_prefs/` — account and config

**Nest thermostat artifacts:**
- Temperature setpoints over time (proves occupancy patterns)
- Auto-away detection events (proves absence)
- Manual schedule changes

**Nest camera artifacts:**
- Motion event history
- Person/animal/package detection events
- Subscription (Aware) history for event clips

**Google Assistant interaction history:**
- Similar to Alexa utterances
- Can be very detailed if user has activity tracking on

**Smart home device list:**
- Paired devices inventory
- Rooms and groupings
- Routines configured

```rust
pub struct GoogleHomeArtifact {
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub device_name: Option<String>,
    pub device_type: Option<String>,
    pub event_data: HashMap<String, String>,
    pub home_name: Option<String>,
    pub user_email: Option<String>,
}
```

**Cross-ecosystem correlation:**
Users sometimes have both Alexa and Google Home devices.
Correlate events between ecosystems for comprehensive timeline.

Emit `Artifact::new("Google Home Event", path_str)`.
MITRE: T1005, T1430.
forensic_value: High.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT IOT-3 — Ring Doorbell and Security System

Create `plugins/strata-plugin-phantom/src/ring_doorbell.rs` (or carbon
for mobile — depending on where Ring app artifacts live best).

**Problem statement:**
Ring doorbells and Ring security systems are on millions of homes.
They capture:
- Video clips of every motion/ring event
- Visitor detection timestamps
- Who accessed what feed and when
- Family/household member activity via app

**Implementation:**

**Ring mobile app:**

iOS: `com.ring.app` container
Android: `com.ringapp`

Parse:
- Device inventory (cameras, doorbells, alarms)
- Event history (rings, motion, alarms)
- Notification history
- Shared user list (who else has app access)
- Video clip references (with thumbnails stored locally)

```rust
pub struct RingEvent {
    pub event_id: String,
    pub event_type: String,          // Ring/Motion/Alarm/DoorbellPress
    pub timestamp: DateTime<Utc>,
    pub device_name: String,
    pub device_location: Option<String>,
    pub video_clip_reference: Option<String>,
    pub audio_available: bool,
    pub person_detected: Option<bool>,
    pub shared_users: Vec<String>,
}
```

**Subscription data:**
- Ring Protect subscription status
- Event clip retention period
- Recording settings

**User access logs:**
Ring tracks which user account viewed which video clips:
- Proves who had access to footage
- Evidence chain for video evidence authenticity

**Correlation with Alexa:**
Ring integrates with Alexa — correlate Ring events with Alexa
announcements ("Someone is at the front door").

**Forensic significance:**
- Home arrival/departure verification
- Visitor identification evidence
- Insurance fraud detection
- Burglary timeline reconstruction

Emit `Artifact::new("Ring Doorbell Event", path_str)`.
MITRE: T1005, T1430.
forensic_value: High — video evidence primary source.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT IOT-4 — Smart TV Ecosystem (Roku, Samsung, LG, Apple TV)

Create `plugins/strata-plugin-nimbus/src/smart_tv.rs`.

**Problem statement:**
Smart TVs are computers in the living room:
- Streaming viewing history (proves content consumed)
- Voice searches (via remote)
- App usage patterns
- Account logins (reveals subscriptions)

**Implementation:**

**Roku artifacts (via paired phone app):**
- `com.roku.remote` / `com.roku.mobile` containers
- Device inventory
- Recent channels accessed
- Voice search history
- Account identifiers

**Samsung Smart TV:**
- Via Samsung SmartThings app
- Connected TV inventory
- Account pairing history

**LG Smart TV:**
- Via LG ThinQ app
- Similar data to Samsung

**Apple TV:**
- Heavily integrated with iOS/macOS ecosystem
- Shared photos, shared viewing
- TV remote in Control Center history

**Viewing history (platform-specific):**
- Netflix app local cache
- Hulu app artifacts
- Disney+ viewing patterns
- YouTube TV channel history

```rust
pub struct SmartTVArtifact {
    pub artifact_type: String,
    pub platform: String,              // Roku/Samsung/LG/AppleTV
    pub timestamp: DateTime<Utc>,
    pub device_name: Option<String>,
    pub content_title: Option<String>,
    pub content_platform: Option<String>, // Netflix/Hulu/Disney+/etc
    pub watch_duration_seconds: Option<u64>,
    pub account: Option<String>,
}
```

**Voice search history:**
Particularly important for cases involving specific content searches.

**Forensic significance:**
- Content consumption evidence (CSAM cases — streaming platforms)
- Home presence (TV use = person present)
- Interest/behavior patterns

Emit `Artifact::new("Smart TV Activity", path_str)`.
MITRE: T1005.
forensic_value: Medium-High depending on case.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT IOT-5 — Smart Locks and Security Systems

Create `plugins/strata-plugin-phantom/src/smart_locks.rs`.

**Problem statement:**
Smart locks log entry/exit with precise timestamps and user identification:
- August, Yale, Schlage Encode, Kwikset Halo
- Entry timestamps with user identification
- Lock/unlock history (who, when, how — pin/app/keypad)
- Auto-lock settings (proves user's security habits)

**Implementation:**

**Smart lock mobile apps:**

August: `com.august.luna`
Yale: `com.yalehome.assureapp`
Schlage: `com.schlage.sense`
Kwikset: `com.kwikset.kevo`

Parse:
- Lock inventory with location/install info
- Access codes list (who has entry codes)
- Entry/exit event history
- Auto-lock triggers
- Battery level history (proves device was active)

```rust
pub struct SmartLockEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub lock_name: String,
    pub lock_location: Option<String>,
    pub event_type: String,             // Lock/Unlock/AutoLock/CodeEntered
    pub actor: Option<String>,          // User name or "Unknown"
    pub method: String,                 // App/Keypad/Key/Auto
    pub successful: bool,
}
```

**Alarm system artifacts:**
- ADT, Ring Alarm, SimpliSafe apps
- Arm/disarm history
- Trigger events
- Zone activity

**Apple HomeKit lock integration:**
Parse HomeKit database for integrated lock activity:
- `~/Library/Preferences/com.apple.Home.plist` (iOS/macOS)

**Forensic significance:**
- Who entered the home and when (crucial in domestic cases)
- Alibi verification
- Scene of crime timeline
- Unauthorized access evidence

Emit `Artifact::new("Smart Lock Event", path_str)`.
MITRE: T1430.
forensic_value: High — primary entry/exit evidence.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 2 — WEARABLES
# ═══════════════════════════════════════════════════════

## SPRINT WEAR-1 — Fitbit Deep Database Parsing

Create `plugins/strata-plugin-pulse/src/wearables/fitbit.rs` (iOS and Android).

**Problem statement:**
Fitbit devices capture comprehensive lifestyle data:
- Step count by minute
- Heart rate by minute (with elevated alerts)
- Sleep stages with timestamps
- GPS tracks for workouts
- Exercise detection
- Weight and body measurements
- Elevation data

This data has solved cases (famously the 2017 Connie Dabate murder case
where Fitbit data contradicted husband's alibi).

**Implementation:**

**Fitbit mobile app artifacts:**

iOS: `com.fitbit.FitbitMobile`
Android: `com.fitbit.FitbitMobile`

Key databases:
- `FitbitMobile.sqlite` — main database
- `Settings.plist` / `shared_prefs/` — account, sync settings

**Tables to parse:**
- `activity_log` — exercise sessions
- `step_minute` — minute-by-minute steps (SMOKING GUN data type)
- `heart_rate_minute` — minute-by-minute heart rate
- `sleep_log` — sleep sessions with stage breakdown
- `food_log` — nutrition tracking
- `weight_log` — weight history
- `badge_earned` — achievement timestamps

```rust
pub struct FitbitMinuteData {
    pub timestamp: DateTime<Utc>,
    pub data_type: String,     // Steps/HeartRate/Active/Sedentary
    pub value: f64,
    pub device_id: String,
}

pub struct FitbitWorkout {
    pub workout_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub workout_type: String,
    pub distance_meters: Option<f64>,
    pub calories_burned: Option<u32>,
    pub avg_heart_rate: Option<u16>,
    pub gps_track: Vec<GpsPoint>,
}

pub struct FitbitSleepSession {
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_minutes: u32,
    pub stages: Vec<SleepStage>,
    pub wake_count: u8,
    pub efficiency_score: Option<u8>,
}
```

**Critical forensic applications:**
- Heart rate spike at time of incident (emotional response indicator)
- Step count during claimed sleep period (contradicts alibi)
- GPS track during workout (places person at specific location)
- Sleep data during crime window (contradicts home claim)

**Integration with obstruction scoring:**
If fitness app data suddenly deleted around incident date, flag as
potential evidence destruction.

Emit `Artifact::new("Fitbit Minute Data", path_str)`.
Emit `Artifact::new("Fitbit Workout", path_str)`.
Emit `Artifact::new("Fitbit Sleep Session", path_str)`.
MITRE: T1430 (via activity patterns), T1005.
forensic_value: High — court-tested evidence type.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT WEAR-2 — Garmin Ecosystem

Create `plugins/strata-plugin-pulse/src/wearables/garmin.rs`.

**Problem statement:**
Garmin devices (watches and bike computers) capture highly detailed
GPS and fitness data:
- Precise GPS tracks (often better than phone)
- Elevation profiles
- Heart rate, cadence, power data
- Multi-day activity history

Garmin is primary wearable choice for athletes, military, and outdoor
enthusiasts. Critical in cases involving:
- Outdoor incidents
- Long-distance travel
- Claimed physical activities

**Implementation:**

**Garmin Connect mobile app:**

iOS: `com.garmin.connect.mobile`
Android: `com.garmin.android.apps.connectmobile`

Parse:
- Activity database (runs, bikes, hikes, swims)
- FIT file references (native Garmin activity format)
- GPS tracks with high resolution
- Workout metrics (VO2 max, training load, recovery)
- Device sync history (which device synced when)

**FIT file format parsing:**
Garmin .fit files contain detailed activity data.
Parse:
- Record messages (per-second GPS + sensor data)
- Session messages (activity summary)
- Lap messages (split data)

```rust
pub struct GarminActivity {
    pub activity_id: String,
    pub activity_type: String,
    pub start_time: DateTime<Utc>,
    pub duration_seconds: u32,
    pub distance_meters: Option<f64>,
    pub gps_points: Vec<GpsPoint>,        // Full track
    pub heart_rate_data: Vec<(DateTime<Utc>, u16)>,
    pub elevation_data: Vec<(DateTime<Utc>, f64)>,
    pub device_model: String,
}
```

**Connect IQ store data:**
Third-party apps installed on Garmin device may create additional artifacts.

**Forensic significance:**
- Precise location history (better than phone for outdoor activity)
- Physical activity level (contradicts sedentary claims or vice versa)
- Heart rate spikes correlate with emotional events

Emit `Artifact::new("Garmin Activity", path_str)`.
MITRE: T1430, T1005.
forensic_value: High.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT WEAR-3 — Apple Watch Deep Parse

Enhance existing iOS Health/HealthKit parsing in Pulse.

**Problem statement:**
Apple Watch data flows into iOS Health but there are Watch-specific
artifacts worth deeper extraction:
- Watch Face usage (proves active use vs idle)
- Digital Crown interaction events
- Workout auto-detection timestamps
- ECG readings (medical evidence quality)
- Blood oxygen readings
- Fall detection events
- Crash detection events (Series 8+)

**Implementation:**

**HealthKit data deeper parsing:**
Location: `/private/var/mobile/Library/Health/healthdb_secure.sqlite`
and `healthdb.sqlite`

Extract additional data types:
- `HKQuantityTypeIdentifierHeartRateVariabilitySDNN` — HRV (stress indicator)
- `HKCategoryTypeIdentifierMindfulSession` — meditation sessions
- `HKCategoryTypeIdentifierAppleStandHour` — proves activity
- `HKDataTypeSleepAnalysis` — enhanced sleep (Apple Watch enables this)
- ECG Waveform data (`ecg_samples` tables)
- Blood oxygen measurements
- Wrist temperature readings (Series 8+)

**Fall detection and crash detection:**
Location: `/private/var/mobile/Library/Preferences/com.apple.health.plist`
and related.
Critical events with precise timestamps — auto-calls emergency services.

**Workout routes:**
Path: `/private/var/mobile/Library/Health/Workouts/`
Extract GPS routes from all Apple Watch workouts.

**Watch face configuration history:**
Different watch faces may reveal user preferences or notifications patterns.

```rust
pub struct AppleWatchMedicalEvent {
    pub event_type: String,            // ECG/BloodOxygen/FallDetection/CrashDetection
    pub timestamp: DateTime<Utc>,
    pub severity: Option<String>,
    pub readings: HashMap<String, f64>,
    pub alert_triggered: bool,
    pub emergency_services_contacted: bool,
}
```

**Forensic significance:**
- Fall detection/Crash detection = precise incident timestamps
- ECG readings during incident = medical evidence of emotional state
- Sleep data = alibi verification
- Workout routes = location evidence

Emit `Artifact::new("Apple Watch Medical Event", path_str)`.
MITRE: T1430, T1005.
forensic_value: Very High — medical-grade evidence.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 3 — GAMING CONSOLES
# ═══════════════════════════════════════════════════════

## SPRINT GAME-1 — PlayStation 4/5 Artifacts

Create `plugins/strata-plugin-specter/src/playstation.rs` — specter
because PS is a non-PC gaming device, specter handles device artifacts.

**Problem statement:**
PlayStation 4 and 5 are primary communication platforms for minors and
a significant ICAC investigation target. Native console imaging is
hard, but associated mobile app and web artifacts on seized computers/
phones are accessible.

**Implementation:**

**PlayStation App mobile (iOS and Android):**

iOS: `com.scea.psapp` / `com.scea.psmobile`
Android: `com.scee.psxandroid` / `com.scea.sps`

Parse:
- Account info (PSN ID, email)
- Friend list with PSN IDs
- Recent messages (text chat)
- Game library and recent plays
- Trophy/achievement history (timestamps)
- Share/screenshot history
- Party invites

**PSN web artifacts on seized PCs:**
Browser history showing `my.playstation.com` access, PSN store purchases.

**Captured content:**
- Screenshots with metadata
- Video clips (date, time, game context)
- Transferred content to/from phone

```rust
pub struct PlayStationArtifact {
    pub psn_id: String,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub game_title: Option<String>,
    pub friends_involved: Vec<String>,
    pub message_content: Option<String>,
    pub trophy_data: Option<TrophyData>,
}

pub struct TrophyData {
    pub trophy_name: String,
    pub trophy_rarity: String,
    pub earned_timestamp: DateTime<Utc>,
    pub game_title: String,
}
```

**Party chat artifacts:**
Party chat members may be listed with timestamps. Critical for ICAC
as predators often use party chat for voice communication with minors.

**Forensic significance:**
- Communication with minors (ICAC critical)
- Game library reveals interests
- Trophy timestamps prove active play
- Message history reveals conversations
- Friend additions reveal social connections

Emit `Artifact::new("PlayStation Activity", path_str)`.
MITRE: T1005.
forensic_value: High — ICAC primary evidence source.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT GAME-2 — Xbox Live Artifacts

Create `plugins/strata-plugin-specter/src/xbox.rs`.

**Problem statement:**
Xbox Live platform for Xbox One, Series X|S. Tightly integrated with
Microsoft account and Windows. Significant ICAC presence.

**Implementation:**

**Xbox app on Windows:**
Location: `%LOCALAPPDATA%\Packages\Microsoft.XboxApp_*\`
- LocalState folder with user data
- Game DVR captures
- Friend list
- Message history

**Xbox app mobile (iOS/Android):**
iOS: `com.microsoft.xboxone.smartglass`
Android: `com.microsoft.xboxone.smartglass`

**Parse:**
- Gamertag and account
- Friends list with gamertags
- Messages (text, voice message metadata)
- Party chat history
- Club memberships (similar to Facebook groups for gaming)
- Game clips and screenshots

**Windows integration:**
Xbox Game Bar on Windows logs to:
- `%LOCALAPPDATA%\Microsoft\GameBar\`
- Screenshots, clips
- Game launch history

```rust
pub struct XboxArtifact {
    pub gamertag: String,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub game_title: Option<String>,
    pub clip_or_screenshot_path: Option<String>,
    pub message_content: Option<String>,
    pub party_members: Vec<String>,
    pub club_name: Option<String>,
}
```

**Xbox Live message history:**
Messages between gamertags — critical ICAC evidence.

**Clips and screenshots:**
Captured content often auto-uploads to Xbox Live cloud.
Local cached versions available for forensic review.

Emit `Artifact::new("Xbox Live Activity", path_str)`.
MITRE: T1005.
forensic_value: High.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT GAME-3 — Nintendo Switch Artifacts

Create `plugins/strata-plugin-specter/src/nintendo.rs`.

**Problem statement:**
Nintendo Switch has lower ICAC footprint than PlayStation/Xbox but:
- Parental controls app has rich data
- Switch Online app tracks play time
- Friend list with Nintendo accounts

**Implementation:**

**Nintendo Switch Online mobile app:**

iOS: `com.nintendo.znca`
Android: `com.nintendo.znca`

Parse:
- Nintendo account linked
- Play time per game (minute precision)
- Friends list
- Voice chat history
- News and announcements read

**Parental Controls app (Nintendo Switch Parental Controls):**

iOS: `com.nintendo.zaaa`
Android: `com.nintendo.zaaa`

Parse:
- Daily play time logs per game
- Content restrictions history
- Bedtime enforcement logs
- Parent account linked

**Screenshots and videos:**
Switch captures stored on:
- MicroSD card (if available)
- Phone via album transfer

```rust
pub struct NintendoArtifact {
    pub nintendo_account: String,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub game_title: Option<String>,
    pub play_duration_minutes: Option<u32>,
    pub friend_interactions: Vec<String>,
    pub screenshot_path: Option<String>,
}
```

**Forensic significance:**
- Parental control logs = minor's activity evidence
- Play time during crime window = digital alibi
- Social connections via friend list

Emit `Artifact::new("Nintendo Switch Activity", path_str)`.
MITRE: T1005.
forensic_value: Medium-High depending on case.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 4 — DRONES
# ═══════════════════════════════════════════════════════

## SPRINT DRONE-1 — DJI Drone Flight Log Parser

Create `plugins/strata-plugin-specter/src/dji.rs`.

**Problem statement:**
DJI is the dominant drone manufacturer. Drones are increasingly encountered
in:
- Border smuggling investigations
- Industrial espionage
- Stalking and trespass cases
- Terrorism investigations

DJI drones produce highly detailed flight logs including GPS tracks,
altitude, takeoff/landing points, and home point coordinates.

**Implementation:**

**DJI Fly app mobile artifacts:**

iOS: `com.dji.fly` / `com.dji.go` / `com.dji.goapp`
Android: `dji.go.v4` / `dji.go.v5` / `dji.pilot`

Parse:
- Flight log files (.txt and .DAT formats)
- Flight records database
- Paired drone inventory (serial numbers)
- Account info (DJI account email)

**Flight log parsing:**
DJI flight logs contain:
- Timestamps per second
- GPS coordinates (high precision)
- Altitude (barometric and GPS)
- Home point coordinates (pilot location)
- Takeoff location
- Landing location
- Battery level over time
- Motor telemetry
- Gimbal orientation
- Camera settings

```rust
pub struct DJIFlightLog {
    pub flight_id: String,
    pub aircraft_serial: String,
    pub aircraft_model: String,
    pub pilot_account: String,
    pub flight_start: DateTime<Utc>,
    pub flight_end: DateTime<Utc>,
    pub duration_seconds: u32,
    pub home_point: GpsPoint,
    pub takeoff_point: GpsPoint,
    pub landing_point: GpsPoint,
    pub flight_track: Vec<FlightTrackPoint>,
    pub max_altitude_meters: f64,
    pub max_distance_meters: f64,
    pub total_distance_meters: f64,
    pub photos_captured: u32,
    pub videos_captured: u32,
}

pub struct FlightTrackPoint {
    pub timestamp: DateTime<Utc>,
    pub lat: f64,
    pub lng: f64,
    pub altitude_m: f64,
    pub speed_mps: f64,
    pub battery_percent: u8,
}
```

**Geofence violation detection:**
Flag flights that entered restricted airspace:
- No-fly zones (airports, military, stadiums)
- Temporary flight restrictions (VIP movements)
- International border crossings

**Paired devices:**
Drones paired to a phone's DJI app are identifiable by serial. Multiple
drones linked to same account may indicate drone smuggling operation.

**DJI Cloud sync:**
Some flight data syncs to DJI Cloud. Local cache on phone has subset.

**Captured media:**
Photos/videos shot by drone stored on phone via DJI app:
- EXIF data with GPS coordinates
- Timestamps matching flight log

**Forensic significance:**
- Proves pilot location (home point)
- Proves drone location over time
- Reveals flight patterns (surveillance, reconnaissance)
- Captures what drone photographed/filmed
- Evidence of geofence violations

Emit `Artifact::new("DJI Flight Log", path_str)`.
MITRE: T1430 (location), T1005.
forensic_value: Very High — often unique physical evidence.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

## SPRINT DRONE-2 — Autel / Skydio / Parrot Drone Support

Extend drone parsing to other manufacturers.

**Problem statement:**
While DJI dominates market share, Autel, Skydio, and Parrot drones
are significant especially in US market (Skydio is American, often
purchased by government/enterprise for US supply chain compliance).

**Implementation:**

**Autel Robotics:**
- Autel Explorer mobile app
- Flight logs in similar format to DJI
- Lesser known but growing market share

**Skydio:**
- Skydio mobile app
- Cloud-integrated flight logs
- Enterprise features (fleet management)

**Parrot:**
- FreeFlight mobile app
- Anafi drone logs

Each manufacturer uses different flight log format but captures similar data.

Common output structure (`DroneFlightLog`) regardless of manufacturer.

Emit `Artifact::new("Drone Flight Log", path_str)` with manufacturer field.
forensic_value: Very High.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 5 — AUTOMOTIVE
# ═══════════════════════════════════════════════════════

## SPRINT AUTO-1 — Connected Car Mobile App Artifacts

Create `plugins/strata-plugin-nimbus/src/connected_car.rs`.

**Problem statement:**
Modern cars have companion apps that track:
- Vehicle location history (often better than GPS)
- Door lock/unlock events
- Engine start/stop events
- Charging events (EVs)
- Service history
- Driver behavior data

This competes with Berla's specialized tools but Berla focuses on
onboard extraction. Mobile app artifacts are gold and underserved.

**Implementation:**

**Tesla app:**
iOS: `com.teslamotors.TeslaApp`
Android: `com.teslamotors.tesla`

Parse:
- Vehicle inventory with VIN
- Location history (when app polled vehicle position)
- Charging sessions (where and when)
- Climate control commands (proves owner interacted with vehicle)
- Summon/autopark events
- Service/maintenance alerts

**FordPass:**
iOS: `com.ford.fordpass`
Android: `com.ford.fordpass`

**MyChevrolet / GM myBrand apps:**
iOS: `com.gm.Bryson` and variants
Android: various

**Toyota / Honda / Nissan apps:**
Various package names

**Common data across manufacturers:**
```rust
pub struct ConnectedCarArtifact {
    pub vehicle_make: String,
    pub vehicle_model: String,
    pub vin: Option<String>,
    pub artifact_type: String,         // LocationUpdate/LockEvent/StartEvent/ChargeStart/ServiceAlert
    pub timestamp: DateTime<Utc>,
    pub location: Option<GpsPoint>,
    pub odometer: Option<u32>,
    pub fuel_or_battery_level: Option<f64>,
    pub event_data: HashMap<String, String>,
}
```

**Location history granularity:**
- Tesla: polls every few minutes when app active, can be 15-min intervals
  when app backgrounded
- Most other manufacturers: less frequent, but still valuable

**Forensic significance:**
- Vehicle location timeline
- Proves who drove when (door unlock events)
- Charging location reveals patterns
- Cross-reference with phone location to detect phone/vehicle separation

Emit `Artifact::new("Connected Car Event", path_str)`.
MITRE: T1430.
forensic_value: High — new evidence category.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 6 — CHROMEOS + ADDITIONAL PLATFORMS
# ═══════════════════════════════════════════════════════

## SPRINT CHROMEOS-1 — ChromeOS Forensic Plugin

Create `plugins/strata-plugin-arbor/src/chromeos.rs` (or new plugin if scope warrants).

**Problem statement:**
ChromeOS deployed on Chromebooks dominates education (ICAC cases on
student devices) and growing enterprise presence. Unique forensic
model — largely cloud-based but significant local artifacts.

**Implementation:**

**ChromeOS partition structure:**
- Stateful partition: `/mnt/stateful_partition/`
- User data: `/home/chronos/u-{hash}/`
- Encrypted user data (default)

**Key local artifacts:**

**Browser profile:**
- `/home/chronos/u-{hash}/` — Chrome profile (same as desktop Chrome)
- Already covered by Carbon plugin, but paths differ

**Google Account artifacts:**
- Policy files from enterprise enrollment
- Sign-in history
- Recovery email

**Crosh logs (Chrome OS shell):**
- `/var/log/chrome/` — browser logs
- `/var/log/messages` — system logs
- `/var/log/ui/` — UI events

**Crostini (Linux containers on ChromeOS):**
If user enabled Linux, `/home/chronos/user/crostini/` contains VM data.
Apply ARBOR Linux parsers to Crostini contents.

**Android apps on ChromeOS:**
ChromeOS runs Android apps via container. Artifacts at:
- `/home/.shadow/`
Apply Carbon Android parsers to Android app data.

```rust
pub struct ChromeOSArtifact {
    pub artifact_type: String,
    pub account: Option<String>,       // Google account
    pub enrollment_domain: Option<String>, // For enterprise-enrolled devices
    pub timestamp: DateTime<Utc>,
    pub event_data: String,
}
```

**Enterprise enrollment detection:**
Enterprise-enrolled Chromebooks have policy files revealing:
- Organization domain
- Policies applied (content filtering, app restrictions)
- Supervised user status (important for school devices and minors)

**Forensic significance:**
- Student devices in ICAC cases (supervised minor use)
- Enterprise Chromebooks in insider threat
- Education-issued devices with academic integrity concerns
- Limited but meaningful local evidence

Emit `Artifact::new("ChromeOS Artifact", path_str)`.
MITRE: T1005.
forensic_value: Medium (cloud-dependent platform).

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT CHAT-1 — Deep Encrypted Messaging Coverage

Enhance existing messaging parsers with deeper artifact extraction.

**Problem statement:**
Current encrypted messaging coverage flags app presence but goes
shallow on local artifacts. Deeper parsing surfaces metadata even
when content is encrypted.

**Implementation:**

**Signal Desktop deep parse:**
Location: `%APPDATA%\Signal\config.json` and `sql/db.sqlite`
(encrypted but metadata accessible)

Parse:
- Account phone number (clear-text in config)
- Conversation list (encrypted content but participant metadata visible)
- Message timestamps (metadata, not content)
- Attachment metadata (names, sizes)
- Group membership history

**Telegram Desktop:**
Location: `%APPDATA%\Telegram Desktop\tdata\`
- `tdata/user_data/maps` — partial conversation cache
- `tdata/settings0` — user settings including phone
- Chat session markers

**WhatsApp Business (different from consumer):**
iOS: `net.whatsapp.WhatsAppSMB`
Android: `com.whatsapp.w4b`

Different database schema than consumer WhatsApp. Business messaging
metadata often less encrypted. Critical for commercial investigations.

**Threema / Element / Matrix:**
Enterprise secure messaging platforms. Each has local database files.
Parse presence indicators and metadata.

**Discord voice channel logs:**
Discord has voice channels where participant lists are tracked even
though voice isn't recorded locally. Voice session metadata is valuable.

```rust
pub struct EncryptedMessagingMetadata {
    pub platform: String,
    pub account_identifier: Option<String>,
    pub conversation_count: u32,
    pub total_messages: u32,
    pub date_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    pub participants: Vec<String>,
    pub group_memberships: Vec<String>,
    pub last_activity: Option<DateTime<Utc>>,
    pub encrypted_content_present: bool,
}
```

Emit `Artifact::new("Encrypted Messaging Metadata", path_str)`.
forensic_value: High — metadata alone often sufficient for investigation scope.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 7 — FINANCIAL + RIDE-SHARE + DATING
# ═══════════════════════════════════════════════════════

## SPRINT FIN-1 — Financial and Payment Apps

Create `plugins/strata-plugin-pulse/src/financial.rs`.

**Problem statement:**
Financial apps reveal financial activity, account access, transaction
patterns, and payment history. Often minimal forensic coverage.

**Implementation:**

**Banking apps (iOS/Android):**
- Chase, Bank of America, Wells Fargo, Capital One
- Parse: login timestamps, recent account list, transaction reference IDs
- Usually no transaction details cached locally (encrypted/cloud)

**Payment apps:**
- Venmo (`com.venmo`) — transaction history cache
- Zelle — integrated into banking apps
- Cash App (`com.squareup.cash`) — transaction metadata
- Apple Pay (deeper than current coverage) — card details, transaction history
- Google Pay — similar

**Investment apps:**
- Robinhood — trade history, watchlist, account activity
- E*Trade, Fidelity, Schwab — login and recent view history

**Tax software:**
- TurboTax — saved filings, income info, deductions
- H&R Block — similar data
- Major financial history disclosure

```rust
pub struct FinancialAppArtifact {
    pub platform: String,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub amount: Option<f64>,
    pub counterparty: Option<String>,
    pub description: Option<String>,
    pub account_reference: Option<String>,  // Last 4 digits
}
```

**Forensic significance:**
- Money laundering investigations
- Fraud cases
- Financial abuse cases
- Tax evasion
- Purchase evidence

Emit `Artifact::new("Financial App Activity", path_str)`.
MITRE: T1005.
forensic_value: High for financial crimes.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

## SPRINT RIDE-1 — Ride-Share and Delivery Apps

Create `plugins/strata-plugin-pulse/src/rideshare.rs`.

**Problem statement:**
Ride-share and food delivery apps reveal movement patterns that
phone GPS may not fully capture. Especially valuable when phone
location services were disabled but app still tracked trips.

**Implementation:**

**Ride-share apps:**
- Uber (`com.ubercab`, `com.ubercab.driver`)
- Lyft (`com.lyft.ios`)
- Parse: trip history with pickup/dropoff locations, times, fare

**Food delivery apps:**
- DoorDash (`com.dd.doordash`)
- UberEats (integrated with Uber)
- GrubHub (`com.grubhub.grubhub`)
- Parse: order history with delivery addresses (often someone else's home)

**Travel apps:**
- Airbnb (`com.airbnb.app`)
- VRBO
- Parse: booking history, rental addresses, trip dates

```rust
pub struct MovementAppArtifact {
    pub platform: String,              // Uber/Lyft/DoorDash/Airbnb/etc
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub pickup_location: Option<GpsPoint>,
    pub pickup_address: Option<String>,
    pub dropoff_location: Option<GpsPoint>,
    pub dropoff_address: Option<String>,
    pub fare: Option<f64>,
    pub driver_name: Option<String>,    // For ride-share
}
```

**Forensic significance:**
- Movement timeline independent of phone GPS
- Proves visits to specific addresses
- Trafficking case evidence (unusual travel patterns)
- Alibi/attribution evidence

Emit `Artifact::new("Movement App Activity", path_str)`.
MITRE: T1430.
forensic_value: High — location timeline.

Zero unwrap, zero unsafe, Clippy clean, three tests minimum.

---

## SPRINT DATE-1 — Dating App Deep Parsing

Create `plugins/strata-plugin-pulse/src/dating.rs`.

**Problem statement:**
Dating apps are encountered in significant portion of investigations:
- Trafficking (solicitation platforms)
- Assault cases (met victim on app)
- Catfishing scams
- Infidelity in divorce cases
- Stalker cases

Current coverage is shallow. Deep parsing matters.

**Implementation:**

**Major dating apps:**
- Tinder (`com.cardify.tinder`)
- Bumble (`com.bumble.app`)
- Hinge (`com.hinge.app`)
- Grindr (`com.grindrapp.android` / `com.grindr`)
- Match (`com.match.matchmobile`)
- OKCupid
- Plenty of Fish

**Specialized dating apps (investigation-relevant):**
- Ashley Madison (infidelity platform)
- Sugar dating apps (SeekingArrangement — trafficking indicators)
- Adult dating apps
- Fetlife
- Christian Mingle / faith-based

**Parse:**
- Account info (email, phone, age stated, photos)
- Match history (who user matched with, when)
- Message history (often locally cached)
- Profile views (who viewed user, who user viewed)
- Location history (dating apps are location-heavy)
- Payment/subscription history
- Reported/blocked users
- Profile pictures (EXIF may leak location)

```rust
pub struct DatingAppArtifact {
    pub platform: String,
    pub account_email: Option<String>,
    pub artifact_type: String,
    pub timestamp: DateTime<Utc>,
    pub matched_user_id: Option<String>,
    pub matched_user_name: Option<String>,
    pub message_content: Option<String>,
    pub location: Option<GpsPoint>,
    pub age_stated: Option<u8>,           // For age verification in cases
}
```

**Age verification critical:**
In ICAC cases, age stated in dating profile is key evidence.
Compare user's stated age in different platforms for inconsistencies.

**Forensic significance:**
- ICAC (predators on dating apps)
- Trafficking (solicitation evidence)
- Assault cases (met victim via app)
- Financial scams (romance fraud)

Emit `Artifact::new("Dating App Activity", path_str)`.
MITRE: T1005.
forensic_value: Very High in specific cases.

Zero unwrap, zero unsafe, Clippy clean, four tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 8 — AI-GENERATED CONTENT DETECTION
# ═══════════════════════════════════════════════════════

## SPRINT AI-1 — AI-Generated Content Detection

Enhance `plugins/strata-plugin-apex/src/exif.rs` + create detection module.

**Problem statement:**
AI-generated images are proliferating. Critical concerns:
- AI-generated CSAM (growing federal investigation priority)
- Deepfake evidence manipulation
- AI-generated fake documents

Detection beyond just EXIF Software field is needed.

**Implementation:**

**Existing EXIF detection (already in Apex):**
Software field matches for: Stable Diffusion, Midjourney, DALL-E,
ComfyUI, Automatic1111, Leonardo.ai

**Add statistical AI detection:**
AI-generated images have statistical patterns:
- Specific noise characteristics in frequency domain
- Common AI artifact signatures (hands, text, physics inconsistencies)
- Missing or synthetic EXIF (real cameras produce consistent EXIF)

**Stable Diffusion metadata in PNG:**
PNG files from Stable Diffusion often have embedded parameters:
- `tEXt` chunks with prompt, negative prompt, model, seed
- Parse and extract

**ComfyUI workflow detection:**
ComfyUI embeds JSON workflow in PNG metadata. Parse to reveal:
- What prompts were used
- What models were used
- Workflow complexity (indicates skill level)

**Local AI tool artifacts:**
- `~/stable-diffusion-webui/` — Automatic1111 installation
- `~/ComfyUI/` — ComfyUI installation
- `~/.cache/huggingface/` — downloaded models
- Prompt history files
- Generation output folders

**AI voice cloning tool artifacts:**
- ElevenLabs API usage artifacts
- Resemble.ai local files
- Tortoise TTS installation

**ChatGPT / Claude / Gemini local caches:**
- Browser LocalStorage for web versions
- Desktop app data paths
- Reveals what user asked AI to do

```rust
pub struct AIGeneratedContent {
    pub file_path: String,
    pub detection_method: String,       // EXIFSoftware/PNGMetadata/Statistical
    pub ai_tool: Option<String>,        // Stable Diffusion/Midjourney/etc
    pub prompt: Option<String>,         // Extracted prompt if available
    pub negative_prompt: Option<String>,
    pub model_used: Option<String>,
    pub generation_timestamp: Option<DateTime<Utc>>,
    pub confidence: f64,
}

pub struct AIInteractionLog {
    pub platform: String,               // ChatGPT/Claude/Gemini
    pub timestamp: DateTime<Utc>,
    pub user_query: Option<String>,
    pub ai_response_summary: Option<String>,
    pub source: String,                 // Browser/Desktop app
}
```

**CSAM-specific considerations:**
When CSAM detection matches an AI-generated image:
- Flag as "AI-Generated CSAM" distinctly from photographic CSAM
- Different legal frameworks apply
- Document detection method for court

**Forensic significance:**
- AI-generated CSAM (federal priority)
- Deepfake evidence manipulation
- Fraud documents
- Understanding suspect's AI toolchain

Emit `Artifact::new("AI-Generated Content", path_str)`.
Emit `Artifact::new("AI Interaction Log", path_str)`.
suspicious=true for AI-generated content in sensitive contexts.
MITRE: T1588.002 (tool acquisition).
forensic_value: Very High — emerging evidence category.

Zero unwrap, zero unsafe, Clippy clean, five tests minimum.

---

# ═══════════════════════════════════════════════════════
# PART 9 — VALIDATION
# ═══════════════════════════════════════════════════════

## SPRINT VALIDATE-v8-1 — Modern Evidence Source Validation

Test all new parsers against real artifacts from Test Material.

Korbyn to add to Test Material:
- Alexa app data from iPhone
- Fitbit sync data
- PlayStation phone app data
- DJI flight log from actual drone
- Tesla app data
- Uber/Lyft app data
- AI-generated images (with and without metadata)

For each source, verify:
1. Plugin correctly identifies the artifact type
2. Extracted data is accurate
3. Cross-plugin correlation works
4. Timeline integration works
5. Report generation includes findings

**Deliverable:**
`FIELD_VALIDATION_v8_REPORT.md` — modern evidence capture benchmarks.

---

# ═══════════════════════════════════════════════════════
# COMPLETION CRITERIA
# ═══════════════════════════════════════════════════════

SPRINTS_v8.md is complete when:

**IoT (Part 1):**
- IOT-1 Alexa, IOT-2 Google Home, IOT-3 Ring, IOT-4 Smart TV, IOT-5 Smart Locks all shipped

**Wearables (Part 2):**
- WEAR-1 Fitbit, WEAR-2 Garmin, WEAR-3 Apple Watch deep all shipped

**Gaming (Part 3):**
- GAME-1 PlayStation, GAME-2 Xbox, GAME-3 Nintendo all shipped

**Drones (Part 4):**
- DRONE-1 DJI, DRONE-2 other manufacturers all shipped

**Automotive (Part 5):**
- AUTO-1 Connected car mobile apps shipped

**ChromeOS + Platforms (Part 6):**
- CHROMEOS-1 shipped
- CHAT-1 deep encrypted messaging enhanced

**Specialized apps (Part 7):**
- FIN-1 financial, RIDE-1 rideshare, DATE-1 dating all shipped

**AI Detection (Part 8):**
- AI-1 AI-generated content detection shipped

**Validation (Part 9):**
- VALIDATE-v8-1 confirms real-world extraction

**Quality gates:**
- All tests passing
- Clippy clean
- Zero unwrap/unsafe/println introduced
- Load-bearing tests preserved
- Public API unchanged

**Strategic outcome:**
Strata covers modern evidence categories that Cellebrite and Magnet
charge premium for but underdeliver on. Major competitive differentiation.
Federal agencies gain capabilities they currently lack.

---

*STRATA AUTONOMOUS BUILD QUEUE v8*
*Wolfmark Systems — 2026-04-17*
*Part 1: IoT ecosystems (Alexa/Google Home/Ring/SmartTV/SmartLocks)*
*Part 2: Wearables (Fitbit/Garmin/Apple Watch deep)*
*Part 3: Gaming consoles (PlayStation/Xbox/Nintendo)*
*Part 4: Drones (DJI + Autel/Skydio/Parrot)*
*Part 5: Automotive (connected car mobile apps)*
*Part 6: ChromeOS + deep encrypted messaging*
*Part 7: Financial/Rideshare/Dating apps*
*Part 8: AI-generated content detection*
*Part 9: Validation*
*Mission: Dominate modern evidence sources*
*Execute all incomplete sprints in order. Ship everything.*
