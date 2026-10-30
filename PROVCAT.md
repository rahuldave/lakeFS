# Changes to lakeFS 1.86.0 for provcat

This branch, `provcat`, is lakeFS 1.86.0 with changes for one use. One lakeFS keeps several orgs apart, through the reference access-list server. Each org has a group, a user and a policy on the repositories that start with its name. The provcat project starts and tests this setup with `scripts/lakefs_acl_local.py`.

It is a reference implementation, not a supported product. lakeFS 1.87.0 removed the external authorization server and the access-list server, and moved to the Business Source License 1.1. So this branch stays on 1.86.0, under Apache 2.0.

## Build

```
export GOTOOLCHAIN=go1.26.4
make gen-ui gen-code
git checkout webui/package-lock.json
make build-binaries VERSION=1.86.0
(cd contrib/auth/acl && go build -o ../../../acl-server ./cmd/acl)
```

## Changes to lakeFS

Each change but the last stops one org from reaching another org's data, when lakeFS uses an external authorization server. The last fixes conditional writes that race a commit. With the built-in single-user mode, every permission check passes, so only the checks on names change what lakeFS does.

### Stage and link take only the repository's own storage

`StageObject` and `LinkPhysicalAddress` in `pkg/api/controller.go` took any physical address. A user who could write to one repository could link another repository's object, and read it.

- An address outside the repository's storage namespace now needs `fs:ImportFromStorage` on that address, as an import does.
- An address with a `.` or `..` segment is refused, also when it is percent-encoded.

lakeFS Enterprise 1.103.0 made the same permission change to stage and link.

### Storage namespaces have no tricks

`CreateRepository` refuses a storage namespace with a `.` or `..` segment, or with `@`, `?` or `#`. A namespace such as `local://acme-x/../globex-y` matched a policy on `namespace/local://acme-*`, but named globex's storage. The commit cache read `local://acme-x@globex-y` as storage of `globex-y`.

### Meta-range IDs are plain names

A commit's `source_metarange`, a commit record's `metarange_id` and the meta-range IDs of a restore were opened as file names. So `../` reached any file on the server.

- `graveler.ValidateMetaRangeID` takes only letters, digits, `_` and `-`.
- A commit that names its meta-range checks that it exists. If it does not, lakeFS answers 404.
- The commit cache, `pkg/pyramid`, refuses absolute file names and `.` or `..` segments.

### A conditional write that lands is not refused

An S3 gateway put with `If-None-Match: *` checks that the key is absent, and then stages the object. `safeBranchWrite` in `pkg/graveler/graveler.go` checks the branch's staging token after the write. If a commit sealed the token meanwhile, it writes again to the new token. The second try checked the condition again, found the first try's object in the sealed token, and failed. So the client got 412, although its object was written and went into the commit.

`Set` now remembers that a try staged the value. A later try accepts a current value equal to its own, in identity and in data. The identity is a hash of size, ETag, metadata and content type, so two uploads of the same bytes share it. The data holds the physical address, which is new for every upload. So a value of another writer still fails the condition, even with the same content.

lakeFS Enterprise 1.107.0 notes the same fix. Open-source lakeFS 1.88.0 still has the bug.

## Changes to the access-list server

The access-list server's code is in `contrib/auth/acl`.

### Callers need a token

The server took every caller, so anyone who reached its port could make an admin. It now takes `api_token`, also from `ACLSERVER_API_TOKEN`. It refuses an API call without `Authorization: Bearer <token>`. lakeFS sends its `auth.api.token` that way. `/_health` stays open. With no token set, the server takes every caller as before, and logs a warning.

### The policy calls work

The server answered 501 to these, and lakeFS passed that on as 500:

- listing policies;
- deleting a policy;
- detaching a policy from a group;
- attaching a policy to a user, or detaching one from a user.

They now work. Deleting a policy removes the policy first, then every link to it, so no link is left for a new policy of the same name. A retried delete removes links that a failed one left. An attach checks again after it writes, so it leaves no link to a policy deleted meanwhile.

### Users and groups take what is theirs

- Deleting a user deletes its keys, so a new user of the same name does not get them.
- Deleting a group deletes its `ACL(_-_)<group>` policy, so no stale one waits for a new group of the same name.

### The admin's own policy is guarded

Each group made through the access-list levels has a policy named `ACL(_-_)<group>`. Deleting the Admins one locked the admin out, with no way back through the API. So the server refuses these:

- deleting the Admins group;
- deleting the `ACL(_-_)` policy of a group that exists, or detaching it from its own group;
- making an `ACL(_-_)` policy for a group that does not exist;
- writing anything into `ACL(_-_)Admins` but the Admin statement.

lakeFS's own `WriteGroupACL` still works for every group but Admins. The admin can still lock itself out in other ways, such as leaving the Admins group. provcat's `scripts/lakefs_acl_local.py --repair-admin` undoes those, through the token.

## Tests

- **`pkg/api/physical_address_test.go`:** the checks on addresses and storage namespaces.
- **`pkg/graveler/graveler_test.go`, `TestValidateMetaRangeID`:** the meta-range ID rule.
- **`pkg/pyramid/filename_test.go`:** the cache's file names.
- **`pkg/graveler/conditional_retry_test.go`:** a conditional write whose token a commit seals, alone, against another writer, and against another writer of the same content.
- **`contrib/auth/acl/serve_test.go`:** the token, the policy calls, deletes, users, groups and the guards, over HTTP.
- **provcat's `tests/system/test_lakefs_acl.py`:** each attack above against real servers. It checks isolation through the API, the S3 gateway and provcat, and runs the admin repair.

`go test ./pkg/api ./pkg/graveler/... ./pkg/catalog/... ./pkg/gateway/... ./pkg/pyramid/... ./contrib/auth/...` passes.

## Known limits

- The guards cover the admin's own policy, not every way an admin can harm itself.
- lakeFS caches each user's policies for up to 23 seconds, so a revoked policy can work that long.
- Error messages and stat replies show absolute server paths.
- `Graveler.Update` passes a condition through the same retry, and keeps the old behaviour. No code outside the tests calls it with a condition.
