# Keycloak Realm export and import

The `import/realm.json` is loaded when the Keycloak service is spun up through
docker-compose. In the top-level directory:

```bash
docker-compose up -d
```

You can now log in via `http://localhost:8080` with the `admin`/`admin` credentials.

## Exporting the Realm

In short - exporting through the admin UI (rightfully) obfuscates client secrets and
user credentials. However, for reproducible builds/environments, we want to include
this data in the Realm export.

Ensure the service is up and running through docker-compose.

Ensure that UID `1000` can write to `./docker/import/`:

```bash
chmod o+rwx ./docker/import/
```

Then open another terminal and run:

```bash
docker-compose exec keycloak \
   /opt/keycloak/bin/kc.sh \
   export \
   --file /opt/keycloak/data/import/test-realm.json \
   --realm test
```
