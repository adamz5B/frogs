//! The ref-free `openapi.yaml` the golden backward-compatibility test generates from. It uses
//! schema refs, a media-type ref, security and one unsafe path, but no parameter, request-body,
//! response or path-item refs and no `~` escapes.

pub(super) const GOLDEN_SPEC: &str = r##"openapi: 3.2.0
info: { title: golden, version: '1' }
security:
  - keyAuth: []
components:
  securitySchemes:
    keyAuth: { type: apiKey, in: header, name: X-Key }
    other: { type: apiKey, in: query, name: k }
  mediaTypes:
    CarJson:
      schema: { $ref: '#/components/schemas/Car' }
  schemas:
    Owner:
      type: object
      required: [name]
      properties:
        name: { type: string }
        age: { type: integer }
    Car:
      type: object
      required: [vin]
      properties:
        vin: { type: string }
        price: { type: number, format: double }
        owner: { $ref: '#/components/schemas/Owner' }
        tags: { type: array, items: { type: string } }
        created: { type: string, format: date-time }
    Pet:
      oneOf:
        - { $ref: '#/components/schemas/Cat' }
        - { $ref: '#/components/schemas/Dog' }
      discriminator:
        propertyName: kind
    Cat: { type: object, properties: { kind: { type: string }, lives: { type: integer } } }
    Dog: { type: object, properties: { kind: { type: string }, good: { type: boolean } } }
    Tree:
      type: object
      properties:
        child: { $ref: '#/components/schemas/Tree' }
paths:
  /cars:
    get:
      operationId: listCars
      parameters:
        - { name: limit, in: query, required: false, schema: { type: integer } }
        - { name: X-Trace, in: header, schema: { type: string } }
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: array
                items: { $ref: '#/components/schemas/Car' }
    post:
      operationId: createCar
      security:
        - other: []
      requestBody:
        required: true
        content:
          application/json:
            schema: { $ref: '#/components/schemas/Car' }
      responses:
        '201':
          description: made
          content:
            application/json:
              $ref: '#/components/mediaTypes/CarJson'
  /cars/{vin}:
    get:
      operationId: getCar
      security: []
      parameters:
        - { name: vin, in: path, required: true, schema: { type: string } }
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: { $ref: '#/components/schemas/Car' }
        '404': { description: nope }
    additionalOperations:
      PURGE:
        operationId: purgeCar
        responses:
          '200':
            description: ok
            content:
              application/json:
                schema: { type: string }
  /pets/:
    get:
      operationId: listPets
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: { $ref: '#/components/schemas/Pet' }
  /tree:
    get:
      operationId: getTree
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: { $ref: '#/components/schemas/Tree' }
  /plain:
    get:
      operationId: plain
      responses:
        '200': { description: nothing }
  '/bad/../path':
    get:
      operationId: bad
      responses:
        '200': { description: ok }
"##;
