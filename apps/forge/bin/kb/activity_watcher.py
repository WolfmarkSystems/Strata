import os
import time
import datetime
from pathlib import Path

# CONFIGURE PATHS
STRATA_ROOT = Path(r"D:\Strata")
LOG_OUT = STRATA_ROOT / "apps" / "forge" / "knowledge" / "vault" / "activity_log.md"
MONITOR_DIRS = ["docs", "apps", "crates", "plugins", "scripts"]
IGNORE_DIRS = ["target", "node_modules", ".git", ".gemini", "dist", "__pycache__", "build", "Release", "Debug"]
IGNORE_EXTS = [".exe", ".pdb", ".log", ".obj", ".tlog", ".lastbuildstate", ".recipe", ".svg", ".png", ".jpg", ".zip"]

def get_file_stats(root_path):
    stats = {}
    for dname in MONITOR_DIRS:
        subdir = root_path / dname
        if not subdir.exists():
            continue
        for root, dirs, files in os.walk(subdir):
            # Prune ignored directories
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix.lower() in IGNORE_EXTS:
                    continue
                try:
                    stats[str(fpath)] = os.path.getmtime(fpath)
                except:
                    pass
    return stats

def log_activity(action, path):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    relative_path = os.path.relpath(path, STRATA_ROOT)
    
    entry = f"\n### [{timestamp}] {action}: {relative_path}\n"
    
    # If it's a small text file, try to capture a snippet
    content_snippet = ""
    if os.path.isfile(path) and action == "CHANGED":
        ext = os.path.splitext(path)[1].lower()
        if ext in [".rs", ".toml", ".md", ".bat", ".ps1", ".py", ".html"]:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    snippet = "".join(lines[:15]) # First 15 lines
                    content_snippet = f"```rust\n{snippet}\n```\n"
            except:
                pass

    msg = entry + (content_snippet if content_snippet else "")
    
    # Write to activity log (keep only last 100 entries for efficiency)
    try:
        current_content = ""
        if LOG_OUT.exists():
            with open(LOG_OUT, "r", encoding="utf-8") as f:
                current_content = f.read()
        
        # Split by header (###)
        parts = current_content.split("\n###")
        if len(parts) > 100:
            parts = parts[-100:]
            current_content = "###".join(parts)
            
        with open(LOG_OUT, "w", encoding="utf-8") as f:
            if not current_content.startswith("# Strata Forge Activity Log"):
                f.write("# Strata Forge Activity Log\nThis file tracks the latest code changes and developments.\n\n")
            f.write(current_content + msg)
    except Exception as e:
        print(f"Error logging: {e}")

def main():
    print(f"Strata Forge Observer started (Watching: {STRATA_ROOT})")
    print(f"Logging to: {LOG_OUT}")
    
    last_stats = get_file_stats(STRATA_ROOT)
    
    while True:
        try:
            time.sleep(5)
            current_stats = get_file_stats(STRATA_ROOT)
            
            # Detect changes/additions
            for fpath, mtime in current_stats.items():
                if fpath not in last_stats:
                    print(f"NEW: {fpath}")
                    log_activity("CREATED", fpath)
                elif mtime > last_stats[fpath]:
                    print(f"CHANGE: {fpath}")
                    log_activity("CHANGED", fpath)
            
            # Detect deletions
            for fpath in last_stats:
                if fpath not in current_stats:
                    print(f"REMOVED: {fpath}")
                    log_activity("DELETED", fpath)
            
            last_stats = current_stats
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error in main loop: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
