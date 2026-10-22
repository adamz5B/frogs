//! What `frogs generate` wrote under `api/datasources/components/` for [`super::golden_spec::GOLDEN_SPEC`],
//! captured from the build before `$ref` resolution (relative path, content with CRLF
//! normalised to LF).

pub(super) const GOLDEN_COMPONENTS: &[(&str, &str)] = &[
    (
        "api/datasources/components/Car.json",
        r##"{
  "_hash": "3da51ee10d613bcc",
  "vin": "string",
  "price": "number (double)",
  "owner": {
    "$component": "Owner",
    "name": "string",
    "age": "integer"
  },
  "tags": {
    "type": "array",
    "items": "string"
  },
  "created": "string (date-time)"
}"##,
    ),
    (
        "api/datasources/components/Cat.json",
        r##"{
  "_hash": "9b4252a54b1a6d1f",
  "kind": "string",
  "lives": "integer"
}"##,
    ),
    (
        "api/datasources/components/Dog.json",
        r##"{
  "_hash": "97f1825238815391",
  "kind": "string",
  "good": "boolean"
}"##,
    ),
    (
        "api/datasources/components/Owner.json",
        r##"{
  "_hash": "31e17ffbb94f7ce4",
  "name": "string",
  "age": "integer"
}"##,
    ),
    (
        "api/datasources/components/Pet.json",
        r##"{
  "_hash": "da4543fa17cba88e",
  "value": "oneOf<object{kind: string, lives: integer}, object{kind: string, good: boolean}>"
}"##,
    ),
    (
        "api/datasources/components/Tree.json",
        r##"{
  "_hash": "fa17507d4aded621",
  "child": "<circular reference: Tree>"
}"##,
    ),
];
