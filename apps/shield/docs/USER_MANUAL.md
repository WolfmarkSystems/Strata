# Strata Shield User Manual

Version: 1.0
Updated: 2026-03-25
Applies to workspace: `D:\forensic-suite`

## 1. Installation

### 1.1 Prerequisites
- Rust 1.70+ (`cargo --version`)
- Node.js 18+ and npm 9+ (`node --version`, `npm --version`)
- Tauri v2 toolchain (`npm run tauri -- --version` in `gui/`)
- Windows 10/11 recommended for full desktop workflow

### 1.2 Build steps (workspace)
```powershell
cd D:\forensic-suite
cargo build --workspace
```

### 1.3 Build/run GUI (Tauri)
```powershell
cd D:\forensic-suite\gui
npm install
npm run dev
# In another terminal
npm run tauri dev
```

### 1.4 Build/run CLI
```powershell
cd D:\forensic-suite
cargo run -p forensic_cli -- --help
```

## 2. Quick Start

1. Create/open a case database and set case metadata.
2. Load evidence source (GUI `File > Add Evidence` or CLI `open-evidence`).
3. Browse files and artifacts (`file-system`, `artifacts`, `timeline`, `registry`).
4. Run targeted parsers (SRUM, EVTX, PowerShell, Registry, etc.).
5. Verify integrity (`verify`) and generate defensibility outputs (`export`, report generation).

Example CLI quick flow:
```powershell
forensic_cli case init --case case123 --db .\cases\case123.sqlite
forensic_cli open-evidence --path .\evidence\sample.E01
forensic_cli verify --case case123 --db .\cases\case123.sqlite
forensic_cli export --case case123 --db .\cases\case123.sqlite --output .\exports\case123
```

## 3. CLI Reference

This section is generated from live `forensic_cli --help` output.

- Total command nodes: 75
- Leaf commands: 69

### 3.1 Top-level command groups
```text
add-to-notes
amcache-deep
artifacts
bam-dam-activity
browser-forensics
capabilities
carve
case
defender-artifacts
doctor
evtx-security
evtx-sysmon
examine
execution-correlation
export
filetable
hashset
image
ingest
ioc
jumplist-fidelity
lnk-shortcut-fidelity
macos-catalog
ntfs-logfile-signals
ntfs-mft-fidelity
open-evidence
powershell-artifacts
prefetch-fidelity
presets
rdp-remote-access
recent-execution
recycle-bin-artifacts
registry-core-user-hives
registry-persistence
replay
replay-verify
report-skeleton
restore-shadow-copies
scheduled-tasks-artifacts
score
search
services-drivers-artifacts
shimcache-deep
smoke-test
srum
strings
timeline
timeline-correlation-qa
triage-session
unallocated
usb-device-history
user-activity-mru
usn-journal-fidelity
verify
verify-export
violations
violations-clear
watchpoints
wmi-persistence-activity
worker
```

### 3.2 Leaf command catalog (`--help` usage + example)

| Command | Usage | Help/Example |
|---|---|---|
| add-to-notes | forensic_cli.exe add-to-notes [ARGS]... | forensic_cli add-to-notes --help |
| amcache-deep | forensic_cli.exe amcache-deep [ARGS]... | forensic_cli amcache-deep --help |
| artifacts | forensic_cli.exe artifacts [OPTIONS] --case <CASE> --db <DB> | forensic_cli artifacts --help |
| bam-dam-activity | forensic_cli.exe bam-dam-activity [ARGS]... | forensic_cli bam-dam-activity --help |
| browser-forensics | forensic_cli.exe browser-forensics [OPTIONS] | forensic_cli browser-forensics --help |
| capabilities | forensic_cli.exe capabilities [OPTIONS] | forensic_cli capabilities --help |
| carve | forensic_cli.exe carve [ARGS]... | forensic_cli carve --help |
| case init | forensic_cli.exe case init [OPTIONS] | forensic_cli case init --help |
| case set-auto-preset | forensic_cli.exe case set-auto-preset [OPTIONS] | forensic_cli case set-auto-preset --help |
| defender-artifacts | forensic_cli.exe defender-artifacts [OPTIONS] | forensic_cli defender-artifacts --help |
| doctor | forensic_cli.exe doctor [OPTIONS] | forensic_cli doctor --help |
| evtx-security | forensic_cli.exe evtx-security [OPTIONS] | forensic_cli evtx-security --help |
| evtx-sysmon | forensic_cli.exe evtx-sysmon [OPTIONS] | forensic_cli evtx-sysmon --help |
| examine | forensic_cli.exe examine [OPTIONS] | forensic_cli examine --help |
| execution-correlation | forensic_cli.exe execution-correlation [OPTIONS] | forensic_cli execution-correlation --help |
| export | forensic_cli.exe export [OPTIONS] | forensic_cli export --help |
| filetable | forensic_cli.exe filetable [OPTIONS] | forensic_cli filetable --help |
| hashset list | forensic_cli.exe hashset list [OPTIONS] | forensic_cli hashset list --help |
| hashset match | forensic_cli.exe hashset match [OPTIONS] | forensic_cli hashset match --help |
| hashset stats | forensic_cli.exe hashset stats [OPTIONS] | forensic_cli hashset stats --help |
| image | forensic_cli.exe image [OPTIONS] <IMAGE_PATH> | forensic_cli image --help |
| ingest doctor | forensic_cli.exe ingest doctor [OPTIONS] --input <INPUT> | forensic_cli ingest doctor --help |
| ingest inspect | forensic_cli.exe ingest inspect [OPTIONS] --case <CASE> --db <DB> | forensic_cli ingest inspect --help |
| ingest matrix | forensic_cli.exe ingest matrix [OPTIONS] | forensic_cli ingest matrix --help |
| ioc add | forensic_cli.exe ioc add [OPTIONS] --name <NAME> --pattern <PATTERN> | forensic_cli ioc add --help |
| ioc list | forensic_cli.exe ioc list | forensic_cli ioc list --help |
| ioc scan | forensic_cli.exe ioc scan [OPTIONS] --case <CASE> | forensic_cli ioc scan --help |
| jumplist-fidelity | forensic_cli.exe jumplist-fidelity [OPTIONS] | forensic_cli jumplist-fidelity --help |
| lnk-shortcut-fidelity | forensic_cli.exe lnk-shortcut-fidelity [OPTIONS] | forensic_cli lnk-shortcut-fidelity --help |
| macos-catalog | forensic_cli.exe macos-catalog [ARGS]... | forensic_cli macos-catalog --help |
| ntfs-logfile-signals | forensic_cli.exe ntfs-logfile-signals [OPTIONS] | forensic_cli ntfs-logfile-signals --help |
| ntfs-mft-fidelity | forensic_cli.exe ntfs-mft-fidelity [OPTIONS] | forensic_cli ntfs-mft-fidelity --help |
| open-evidence | forensic_cli.exe open-evidence [OPTIONS] [PATH] | forensic_cli open-evidence --help |
| powershell-artifacts | forensic_cli.exe powershell-artifacts [OPTIONS] | forensic_cli powershell-artifacts --help |
| prefetch-fidelity | forensic_cli.exe prefetch-fidelity [OPTIONS] | forensic_cli prefetch-fidelity --help |
| presets list | forensic_cli.exe presets list | forensic_cli presets list --help |
| presets show | forensic_cli.exe presets show --name <NAME> | forensic_cli presets show --help |
| rdp-remote-access | forensic_cli.exe rdp-remote-access [OPTIONS] | forensic_cli rdp-remote-access --help |
| recent-execution | forensic_cli.exe recent-execution [OPTIONS] | forensic_cli recent-execution --help |
| recycle-bin-artifacts | forensic_cli.exe recycle-bin-artifacts [OPTIONS] | forensic_cli recycle-bin-artifacts --help |
| registry-core-user-hives | forensic_cli.exe registry-core-user-hives [OPTIONS] | forensic_cli registry-core-user-hives --help |
| registry-persistence | forensic_cli.exe registry-persistence [OPTIONS] | forensic_cli registry-persistence --help |
| replay | forensic_cli.exe replay [OPTIONS] --case <CASE> --db <DB> | forensic_cli replay --help |
| replay-verify | forensic_cli.exe replay-verify [OPTIONS] --case <CASE> --db <DB> | forensic_cli replay-verify --help |
| report-skeleton | forensic_cli.exe report-skeleton [OPTIONS] --case <CASE> | forensic_cli report-skeleton --help |
| restore-shadow-copies | forensic_cli.exe restore-shadow-copies [OPTIONS] | forensic_cli restore-shadow-copies --help |
| scheduled-tasks-artifacts | forensic_cli.exe scheduled-tasks-artifacts [OPTIONS] | forensic_cli scheduled-tasks-artifacts --help |
| score explain | forensic_cli.exe score explain --row-id <ROW_ID> | forensic_cli score explain --help |
| score rebuild | forensic_cli.exe score rebuild | forensic_cli score rebuild --help |
| search | forensic_cli.exe search [OPTIONS] [QUERY_TEXT] | forensic_cli search --help |
| services-drivers-artifacts | forensic_cli.exe services-drivers-artifacts [OPTIONS] | forensic_cli services-drivers-artifacts --help |
| shimcache-deep | forensic_cli.exe shimcache-deep [ARGS]... | forensic_cli shimcache-deep --help |
| smoke-test | forensic_cli.exe smoke-test [OPTIONS] | forensic_cli smoke-test --help |
| srum | forensic_cli.exe srum [ARGS]... | forensic_cli srum --help |
| strings | forensic_cli.exe strings [OPTIONS] | forensic_cli strings --help |
| timeline | forensic_cli.exe timeline [OPTIONS] | forensic_cli timeline --help |
| timeline-correlation-qa | forensic_cli.exe timeline-correlation-qa [OPTIONS] | forensic_cli timeline-correlation-qa --help |
| triage-session | forensic_cli.exe triage-session [OPTIONS] | forensic_cli triage-session --help |
| unallocated | forensic_cli.exe unallocated [OPTIONS] --case <CASE> --volume <VOLUME> | forensic_cli unallocated --help |
| usb-device-history | forensic_cli.exe usb-device-history [OPTIONS] | forensic_cli usb-device-history --help |
| user-activity-mru | forensic_cli.exe user-activity-mru [ARGS]... | forensic_cli user-activity-mru --help |
| usn-journal-fidelity | forensic_cli.exe usn-journal-fidelity [OPTIONS] | forensic_cli usn-journal-fidelity --help |
| verify | forensic_cli.exe verify [OPTIONS] | forensic_cli verify --help |
| verify-export | forensic_cli.exe verify-export [OPTIONS] --case <CASE> --db <DB> | forensic_cli verify-export --help |
| violations | forensic_cli.exe violations [OPTIONS] | forensic_cli violations --help |
| violations-clear | forensic_cli.exe violations-clear [ARGS]... | forensic_cli violations-clear --help |
| watchpoints | forensic_cli.exe watchpoints [OPTIONS] | forensic_cli watchpoints --help |
| wmi-persistence-activity | forensic_cli.exe wmi-persistence-activity [OPTIONS] | forensic_cli wmi-persistence-activity --help |
| worker | forensic_cli.exe worker [OPTIONS] --case <CASE> | forensic_cli worker --help |

### 3.3 Common command examples
```powershell
forensic_cli verify --case case123 --db .\cases\case123.sqlite
forensic_cli timeline --case case123 --db .\cases\case123.sqlite --limit 200 --json
forensic_cli srum --input .\exports\srum.json --json
forensic_cli evtx-security --input .\exports\Security.evtx --json
forensic_cli powershell-artifacts --history .\artifacts\powershell\ConsoleHost_history.txt --json
forensic_cli triage-session --case case123 --db .\cases\case123.sqlite --strict
```

## 4. GUI Walkthrough

Primary navigation sections in the desktop app:
- `Dashboard`: case health, capability count, task progress, and recent activity.
- `Case Overview`: summary panel for case metadata and workflow state.
- `Evidence Sources`: source list and evidence-path context.
- `File System`: unified file table and tree-backed exploration.
- `Timeline`: timestamped event investigation, filters, source facets, and saved filter presets.
- `Artifacts`: extracted artifact rows, previews, and context actions.
- `Registry`: registry-focused artifact table with LastWrite sorting.
- `Communications`: email/communications artifact view.
- `Browser Data`: browser-scoped filtering on unified rows.
- `Carved Files`: deleted/carved record focus view.
- `Hash Sets`: known-good/known-bad loading and match summary.
- `Reports`: report operation panel for investigator deliverables.
- `Logs`: active job status and run logs.
- `Settings`: defaults, retention behavior, and runtime health checks.

Typical GUI flow:
1. `File > Add Evidence`
2. Verify source in `Evidence Sources`
3. Investigate `File System`, `Artifacts`, `Timeline`, and `Registry`
4. Apply `Hash Sets` for known-good/known-bad triage
5. Export via `Reports`

## 5. Evidence Formats and Filesystems

### 5.1 Ingest matrix (`forensic_cli ingest matrix --json`)
```text
raw/dd/img                 supported
split raw (001/r01/aa)     supported
e01/ex01                   supported
vhd/vhdx                   supported
vmdk                       supported
aff/aff4                   partial
ufed export folder         partial
graykey export folder      partial
```

### 5.2 Additional container readers present in engine modules
- `ISO`, `QCOW2`, `L01`, `DMG`, `VDI`, `LUKS`, `CoreStorage`, `FileVault`, `Storage Spaces`, `LVM`
- Runtime maturity varies by adapter and validation coverage.

### 5.3 Filesystem coverage (from capability registry)
- `NTFS` (Production)
- `FAT`/`FAT32` (Production)
- `exFAT` (Production)
- `ext4` (Production)
- `APFS` (Beta)
- `HFS+` (Stub)
- `XFS` (Stub)

## 6. Artifact Parsing Modules

The classification layer currently includes 275 module entries (root module + 274 declared submodules).

```text
  1. mod
  2. accessibility
  3. aclparse
  4. activedir
  5. ads
  6. amcache
  7. android_apps
  8. applocker
  9. apppool
 10. appx
 11. archive
 12. audio
 13. auditpol
 14. autorun
 15. azure_ad
 16. backup
 17. bitlocker_deep
 18. bitlockervol
 19. bits
 20. bootexec
 21. bootlog
 22. browser
 23. certificate
 24. chromedp
 25. chromepwd
 26. cleanup
 27. cluster
 28. cmd
 29. comobj
 30. computerinfo
 31. crash_dump
 32. crashdmp
 33. credentials
 34. cryptopol
 35. dcominfo
 36. defender
 37. defender_endpoint
 38. detect
 39. dhcplease
 40. discordchat
 41. diskquota
 42. dllhijack
 43. dnscache
 44. dnsinfo
 45. doh
 46. dropbox
 47. dump
 48. dynldll
 49. edge_deep
 50. email
 51. envblock
 52. envvar
 53. errorcodes
 54. errorreporting
 55. etw
 56. etw_deep
 57. eventinfo
 58. eventlog
 59. exchange
 60. exchange_online
 61. exchange_parse
 62. execution_correlation
 63. exif
 64. failover
 65. fileshr
 66. filetype
 67. firefoxdp
 68. firewall
 69. font
 70. fwprofile
 71. googledrive
 72. gpolist
 73. handles
 74. hashdb
 75. hunting
 76. hyperv
 77. iisconfig
 78. iislog
 79. image
 80. ink
 81. installer
 82. ios_apps
 83. jet
 84. jumplist
 85. kerberos
 86. kernel_callbacks
 87. kernmod
 88. layout
 89. ldapinfo
 90. linechat
 91. live_memory
 92. live_process
 93. live_registry
 94. lmcompat
 95. lnk
 96. localgrp
 97. logfile
 98. logonsession
 99. lsasshook
100. macos_artifacts
101. macos_catalog
102. mailslot
103. mappeddrive
104. metadata
105. mftparse
106. microsoft365
107. mobile
108. mutex
109. namedpipe
110. netdriver
111. netreg
112. netshare
113. network
114. nisinfo
115. notifications
116. ntlmhash
117. office
118. office_deep
119. officeaccount
120. onedrive
121. onedriveaccount
122. partitions
123. passwords
124. patchcache
125. pdf
126. pendingren
127. persistence
128. phone_link
129. powershell
130. prefetch
131. prefetchdata
132. preview
133. printjobs
134. printspooler
135. programs
136. psevent
137. quick_assist
138. rdp
139. recentdocs
140. recentfiles
141. recyclebin
142. reg_export
143. regapp
144. regautoplay
145. regbam
146. regbitlocker
147. regcloud
148. regdefendercfg
149. regdesktop
150. regdisk
151. regenv
152. regexpview
153. regie
154. registry
155. registryhive
156. reglogon
157. regmru
158. regmru2
159. regmrupath
160. regoffice
161. regprint
162. regproxy
163. regpwd
164. regsecurity
165. regservice
166. regsysrestore
167. regtask
168. regtime
169. reguac
170. reguninstall
171. regurl
172. regusb
173. reguserassist
174. regwifi
175. regwinver
176. reliabhist
177. restoration
178. restore_shadow
179. saminfo
180. sandbox
181. sccm_parse
182. timeline_correlation_qa
183. triage
184. triage_filter
185. triage_presets
186. user_activity_mru
187. win11timeline
188. windowsimage
189. scalpel
190. sccmcfg
191. schannel
192. schedjob
193. schedreboot
194. scheduledtasks
195. search
196. search_index
197. secevent
198. section
199. selftls
200. servicedll
201. services
202. sessionevt
203. setupapi
204. seven_zip
205. shellbags
206. shims
207. shortcuts
208. signalchat
209. signature
210. skypechat
211. slackchat
212. smbinfo
213. snaplayouts
214. snipping
215. spoolerinfo
216. spotlight
217. sqlite
218. sqlserv
219. srum
220. startup
221. stickynotes
222. storage_spaces
223. strings
224. sysdriver
225. sysenv
226. sysinfo2
227. sysmon
228. sysrestore
229. systeminfo
230. taskbar
231. taskxml
232. teamschat
233. telegramchat
234. terminal
235. thumbcache
236. timesync
237. tpm
238. troubleshooting
239. trustrel
240. updates
241. usb
242. usbhist
243. userassist
244. userrights
245. usnjrnl
246. viberchat
247. video
248. virdir
249. vpn_connections
250. vscode
251. wdigest
252. whatsapp
253. widgets
254. widgets_more
255. wifi_6e
256. win32serv
257. win_sandbox
258. windowsdefender
259. winfeature
260. winlogon
261. winrmcfg
262. winsinfo
263. winsxsinfo
264. wintasks
265. wintimeline
266. wmi
267. wmiinst
268. wmipersist
269. wmitrace
270. wsl
271. wsl2
272. xbox
273. xbox_gamebar
274. yarascan
275. your_phone
```

## 7. AI Guardian (Strata AI)

Strata AI acts as a truthfulness and quality gate around forensic outputs.

Operational guard scripts include:
- `scripts\scan_stubs.ps1`: stub scanner for TODO/unimplemented/default placeholder patterns
- `scripts\validate_envelopes.ps1`: envelope schema validator for CLI result contracts
- `scripts\quality-gate.ps1`: release gate orchestration (tests + docs + benchmarks)

Core guardian doctrine/checklists are under `guardian\` (truthfulness rules, contracts, runtime audit, parser review, release readiness).

## 8. Plugin Development (`.dll` parsers)

Plugin ABI contract (Windows):
- Export `plugin_name()` -> C string
- Export `plugin_version()` -> C string matching engine plugin ABI version
- Export `plugin_create()` -> `*mut dyn Plugin`

Use the reference implementation in `engine/plugins/example/src/lib.rs`.

Minimal workflow:
1. Implement `Plugin` and `ArtifactParser` traits.
2. Compile to `.dll` (`cdylib`).
3. Place plugin binary in the runtime `plugins/` directory.
4. Run evidence workflow and verify plugin artifacts are emitted.

## 9. Troubleshooting

| Symptom | Likely cause | Resolution |
|---|---|---|
| `LNK1104` / file in use during build | Running process still locking binary/object | Close running `forensic_cli.exe` / GUI process and rebuild. |
| Cargo remove/delete failure on Windows (`os error 32`) | File lock/AV scan on `target` artifacts | Retry with dedicated `CARGO_TARGET_DIR`; reduce concurrent jobs; temporarily pause locking process. |
| CLI command returns envelope error | Missing required flags/case/db paths | Run `forensic_cli <command> --help` and provide required fields. |
| GUI shows no data after opening evidence | Evidence path not mounted or parser output empty | Check `Logs`, run `open-evidence` and parser commands in CLI, confirm source paths. |
| Tauri window does not launch | Frontend dev server or Tauri deps missing | Run `npm install`, `npm run dev`, then `npm run tauri dev`. |

## 10. Operational Notes

- Always document parser limitations in final reports.
- Run `verify` before `export` for defensibility workflows.
- Preserve source evidence in read-only mode; write only to output directories.

