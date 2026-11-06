//! What `frogs generate` wrote under `api/datasources/endpoints/` for [`super::golden_spec::GOLDEN_SPEC`],
//! captured from the build before `$ref` resolution (relative path, content with CRLF
//! normalised to LF).

pub(super) const GOLDEN_ENDPOINTS: &[(&str, &str)] = &[
    (
        "api/datasources/endpoints/cars/endpoint.get.json",
        r##"{
  "operationId": "listCars",
  "_generated": true,
  "_todo": "See endpoint.get.reference.json for available request/response fields. Fill in sources and map each response field to a source path.",
  "sources": {},
  "response": {
    "type": "array",
    "source": null,
    "items": null
  },
  "security": "keyAuth"
}"##,
    ),
    (
        "api/datasources/endpoints/cars/endpoint.get.reference.json",
        r##"{
  "operationId": "listCars",
  "_hash": "83c234aca21b3541",
  "security": "keyAuth",
  "request": {
    "query": [
      "limit"
    ],
    "path": [],
    "header": [
      "X-Trace"
    ],
    "body": null
  },
  "response": {
    "type": "array",
    "items": {
      "$component": "Car",
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
    }
  },
  "availableParameterSources": [
    "query.limit",
    "header.X-Trace"
  ]
}"##,
    ),
    (
        "api/datasources/endpoints/cars/endpoint.post.json",
        r##"{
  "operationId": "createCar",
  "_generated": true,
  "_todo": "See endpoint.post.reference.json for available request/response fields. Fill in sources and map each response field to a source path.",
  "sources": {},
  "response": {
    "vin": null,
    "price": null,
    "owner": {
      "name": null,
      "age": null
    },
    "tags": {
      "type": "array",
      "source": null,
      "items": null
    },
    "created": null
  },
  "security": "other"
}"##,
    ),
    (
        "api/datasources/endpoints/cars/endpoint.post.reference.json",
        r##"{
  "operationId": "createCar",
  "_hash": "154a652c35b90284",
  "security": "other",
  "request": {
    "query": [],
    "path": [],
    "header": [],
    "body": null
  },
  "response": {
    "$component": "Car",
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
  },
  "availableParameterSources": []
}"##,
    ),
    (
        "api/datasources/endpoints/cars/{vin}/endpoint.PURGE.json",
        r##"{
  "operationId": "purgeCar",
  "_generated": true,
  "_todo": "See endpoint.PURGE.reference.json for available request/response fields. Fill in sources and map each response field to a source path.",
  "sources": {},
  "response": null,
  "security": "keyAuth"
}"##,
    ),
    (
        "api/datasources/endpoints/cars/{vin}/endpoint.PURGE.reference.json",
        r##"{
  "operationId": "purgeCar",
  "_hash": "37140e51efa8b132",
  "security": "keyAuth",
  "request": {
    "query": [],
    "path": [],
    "header": [],
    "body": null
  },
  "response": "string",
  "availableParameterSources": []
}"##,
    ),
    (
        "api/datasources/endpoints/cars/{vin}/endpoint.get.json",
        r##"{
  "operationId": "getCar",
  "_generated": true,
  "_todo": "See endpoint.get.reference.json for available request/response fields. Fill in sources and map each response field to a source path.",
  "sources": {},
  "response": {
    "vin": null,
    "price": null,
    "owner": {
      "name": null,
      "age": null
    },
    "tags": {
      "type": "array",
      "source": null,
      "items": null
    },
    "created": null
  }
}"##,
    ),
    (
        "api/datasources/endpoints/cars/{vin}/endpoint.get.reference.json",
        r##"{
  "operationId": "getCar",
  "_hash": "154a652c35b90284",
  "security": null,
  "request": {
    "query": [],
    "path": [
      "vin"
    ],
    "header": [],
    "body": null
  },
  "response": {
    "$component": "Car",
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
  },
  "availableParameterSources": [
    "path.vin"
  ]
}"##,
    ),
    (
        "api/datasources/endpoints/pets/endpoint.get.json",
        r##"{
  "operationId": "listPets",
  "_generated": true,
  "_todo": "See endpoint.get.reference.json for available request/response fields. Fill in sources and map each response field to a source path.",
  "sources": {},
  "response": null,
  "security": "keyAuth"
}"##,
    ),
    (
        "api/datasources/endpoints/pets/endpoint.get.reference.json",
        r##"{
  "operationId": "listPets",
  "_hash": "e055750f218df983",
  "security": "keyAuth",
  "request": {
    "query": [],
    "path": [],
    "header": [],
    "body": null
  },
  "response": "oneOf<object{kind: string, lives: integer}, object{kind: string, good: boolean}>",
  "availableParameterSources": []
}"##,
    ),
    (
        "api/datasources/endpoints/plain/endpoint.get.json",
        r##"{
  "operationId": "plain",
  "_generated": true,
  "_todo": "See endpoint.get.reference.json for available request/response fields. Fill in sources and map each response field to a source path.",
  "sources": {},
  "response": null,
  "security": "keyAuth"
}"##,
    ),
    (
        "api/datasources/endpoints/plain/endpoint.get.reference.json",
        r##"{
  "operationId": "plain",
  "_hash": "5b9bc4ba528108e4",
  "security": "keyAuth",
  "request": {
    "query": [],
    "path": [],
    "header": [],
    "body": null
  },
  "response": null,
  "availableParameterSources": []
}"##,
    ),
    (
        "api/datasources/endpoints/tree/endpoint.get.json",
        r##"{
  "operationId": "getTree",
  "_generated": true,
  "_todo": "See endpoint.get.reference.json for available request/response fields. Fill in sources and map each response field to a source path.",
  "sources": {},
  "response": {
    "child": null
  },
  "security": "keyAuth"
}"##,
    ),
    (
        "api/datasources/endpoints/tree/endpoint.get.reference.json",
        r##"{
  "operationId": "getTree",
  "_hash": "814535533dc99fa0",
  "security": "keyAuth",
  "request": {
    "query": [],
    "path": [],
    "header": [],
    "body": null
  },
  "response": {
    "$component": "Tree",
    "child": "<circular reference: Tree>"
  },
  "availableParameterSources": []
}"##,
    ),
];
