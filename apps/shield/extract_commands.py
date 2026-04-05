"""
Bulk extract all remaining run_*_command functions from main.rs into separate module files.
Each module re-exports the function as `pub fn execute(args: Vec<String>)`.
Updates commands/mod.rs and the dispatch block in main.rs.
"""
import re, os

MAIN_RS = r'd:\forensic-suite\cli\src\main.rs'
COMMANDS_DIR = r'd:\forensic-suite\cli\src\commands'

with open(MAIN_RS, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Already extracted commands that have clap modules
CLAP_COMMANDS = {
    'verify', 'capabilities', 'doctor', 'open_evidence', 'export', 'presets', 'score'
}

def extract_function(lines, func_name):
    """Extract function body with proper brace-depth tracking."""
    for i, line in enumerate(lines):
        if line.strip().startswith(f'fn {func_name}('):
            depth = 0
            started = False
            func_lines = []
            for j in range(i, len(lines)):
                func_lines.append(lines[j])
                depth += lines[j].count('{') - lines[j].count('}')
                if lines[j].count('{') > 0:
                    started = True
                if started and depth == 0:
                    return ''.join(func_lines), i, j
    return None, 0, 0

# Find all remaining run_*_command functions
extractions = []
for i, line in enumerate(lines):
    m = re.match(r'^fn (run_\w+_command)\(', line)
    if m:
        func_name = m.group(1)
        mod_name = func_name.replace('run_', '').replace('_command', '')
        if mod_name in CLAP_COMMANDS:
            continue  # Already extracted with clap
        body, start, end = extract_function(lines, func_name)
        if body:
            extractions.append({
                'func_name': func_name,
                'mod_name': mod_name,
                'body': body,
                'start': start,
                'end': end,
                'size': end - start + 1,
            })

print(f"Found {len(extractions)} functions to extract")

# Create module files
created = []
for ext in extractions:
    mod_path = os.path.join(COMMANDS_DIR, f"{ext['mod_name']}.rs")
    if os.path.exists(mod_path):
        print(f"  SKIP (exists): {ext['mod_name']}.rs")
        continue
    
    # Transform: rename the function from run_xxx_command to execute, make it pub
    body = ext['body']
    body = body.replace(f"fn {ext['func_name']}(", "pub fn execute(", 1)
    
    # Write the module file with a re-export of necessary types from crate root
    module_content = f"// Extracted from main.rs — {ext['func_name']}\n"
    module_content += "// TODO: Convert to clap derive args in a future pass\n\n"
    module_content += "use crate::*;\n\n" # Fast way to bring in dependencies for now
    module_content += body
    
    with open(mod_path, 'w', encoding='utf-8') as f:
        f.write(module_content)
    
    created.append(ext['mod_name'])
    print(f"  CREATED: {ext['mod_name']}.rs ({ext['size']} lines)")

print(f"\nCreated {len(created)} new module files")

if not created:
    print("Nothing newly created. Updating main.rs dispatch to match existing modules.")

# Update mod.rs
mod_rs_path = os.path.join(COMMANDS_DIR, 'mod.rs')
with open(mod_rs_path, 'r', encoding='utf-8') as f:
    mod_content = f.read()

# Add new module declarations
new_mods = []
for mod_name in sorted(created):
    decl = f"pub mod {mod_name};"
    if decl not in mod_content:
        new_mods.append(decl)

if new_mods:
    mod_content = mod_content.rstrip() + '\n' + '\n'.join(new_mods) + '\n'
    with open(mod_rs_path, 'w', encoding='utf-8') as f:
        f.write(mod_content)
    print(f"\nAdded {len(new_mods)} module declarations to mod.rs")

# Now update dispatch in main.rs
with open(MAIN_RS, 'r', encoding='utf-8') as f:
    main_content = f.read()

# Make sure we don't accidentally update the clap extracted functions
# which are already properly structured as blocks.
# We're just replacing the simple one-line calls.
rewired_count = 0
for ext in extractions:
    cli_name = ext['mod_name'].replace('_', '-')
    func_name = ext['func_name']
    mod_name = ext['mod_name']
    
    old_call = f'"{cli_name}" => {func_name}(command_args),'
    new_call = f'"{cli_name}" => commands::{mod_name}::execute(command_args),'
    
    if old_call in main_content:
        main_content = main_content.replace(old_call, new_call)
        rewired_count += 1
        print(f"  REWIRED: {cli_name} -> commands::{mod_name}::execute")

with open(MAIN_RS, 'w', encoding='utf-8') as f:
    f.write(main_content)

print(f"\nRewired {rewired_count} commands in main.rs")
print("Done!")
