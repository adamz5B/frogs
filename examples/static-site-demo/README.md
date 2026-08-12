# Static site demo

A tiny multi-page static site — HTML, CSS, and JS across several files — served entirely by
`frogs` itself via a hand-written `webserve.json`. No `openapi.yaml`, no database, no generated
config anywhere in this project.

Demonstrates:

- Multi-file static serving: `index.html`, `about.html`, `css/style.css`, `js/app.js`, each
  resolved straight off disk with the right `Content-Type`.
- A custom 404 page (`404.html`, named as `notFoundPage` in `webserve.json`) — try a broken link
  from the home page.
- Basic HTTP caching: every response carries `ETag`/`Last-Modified`, and a conditional request
  gets a real `304 Not Modified` back (open your browser's network tab and reload, or see the
  `curl` example below).
- `webserve.json` itself is never served, no matter what path is requested.

## Running it

Build a debug binary from the repo root, then run it against this project:

```sh
cargo build
cd examples/static-site-demo
../../target/debug/frogs run
```

Open http://localhost:8090 in a browser and click the "Ribbit!" button a few times, then follow
the "broken link" on the home page to see the custom 404.

Stop it from another terminal (same directory):

```sh
../../target/debug/frogs stop
```

### Checking the caching headers by hand

```sh
curl -i http://localhost:8090/                       # note the ETag header
curl -i http://localhost:8090/ -H 'If-None-Match: <paste the ETag value here>'
# -> HTTP/1.1 304 Not Modified, empty body
```

## Regenerating `webserve.json`

The one here is already checked in, and `frogs generate` never overwrites an existing
`webserve.json`. To see it produced fresh, delete it and run `frogs generate` again — with no
`openapi.yaml` in this directory, it infers `--role web` on its own:

```sh
rm webserve.json
../../target/debug/frogs generate
```
