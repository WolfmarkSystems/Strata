#[cfg(any(feature = "python-plugins", feature = "lua-plugins"))]
use super::discover_and_load_scripts;
#[cfg(any(feature = "python-plugins", feature = "lua-plugins"))]
use std::path::Path;

#[cfg(feature = "python-plugins")]
#[test]
fn test_python_plugin() {
    let py_code = r#"
class Parser:
    name = "Test Python Parser"
    artifact_type = "test_type"
    target_patterns = ["*.txt"]
    
    def parse_file(self, path, data):
        return [{"field1": "value1", "field2": data.decode('utf-8')}]
"#;
    let pdir = tempfile::tempdir().unwrap();
    let py_path = pdir.path().join("test_parser.py");
    std::fs::write(&py_path, py_code).unwrap();

    let parsers = discover_and_load_scripts(pdir.path());
    assert_eq!(parsers.len(), 1);

    let p = &parsers[0];
    assert_eq!(p.name(), "Test Python Parser");
    assert_eq!(p.artifact_type(), "test_type");
    assert_eq!(p.target_patterns(), vec!["*.txt"]);

    let artifacts = p
        .parse_file(Path::new("dummy.txt"), b"hello world")
        .unwrap();
    assert_eq!(artifacts.len(), 1);
    let art = &artifacts[0];
    assert_eq!(
        art.json_data.get("field1").unwrap().as_str().unwrap(),
        "value1"
    );
    assert_eq!(
        art.json_data.get("field2").unwrap().as_str().unwrap(),
        "hello world"
    );
}

#[cfg(feature = "lua-plugins")]
#[test]
fn test_lua_plugin() {
    let lua_code = r#"
return {
    name = "Test Lua Parser",
    artifact_type = "test_type_lua",
    target_patterns = {"*.lua_target"},
    parse_file = function(path, data)
        return {
            { fieldA = "valA", fieldB = data }
        }
    end
}
"#;
    let pdir = tempfile::tempdir().unwrap();
    let lua_path = pdir.path().join("test_parser.lua");
    std::fs::write(&lua_path, lua_code).unwrap();

    let parsers = discover_and_load_scripts(pdir.path());
    assert_eq!(parsers.len(), 1);

    let p = &parsers[0];
    assert_eq!(p.name(), "Test Lua Parser");
    assert_eq!(p.artifact_type(), "test_type_lua");
    assert_eq!(p.target_patterns(), vec!["*.lua_target"]);

    let artifacts = p.parse_file(Path::new("dummy.lua"), b"lua world").unwrap();
    assert_eq!(artifacts.len(), 1);
    let art = &artifacts[0];
    assert_eq!(
        art.json_data.get("fieldA").unwrap().as_str().unwrap(),
        "valA"
    );
    assert_eq!(
        art.json_data.get("fieldB").unwrap().as_str().unwrap(),
        "lua world"
    );
}
