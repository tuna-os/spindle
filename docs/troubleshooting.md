# Troubleshoot a live server

This page is for operators. Each section gives a symptom, a check and a
fix. The examples come from reilly.asia in November 2026.

## Images and avatars do not load

Element X shows "Sorry, an error occurred" for an image, or it shows no
avatars. Check these causes in this order.

### The client asks at the unstable media prefix

Element X 26.11 asks for media at
`/_matrix/client/unstable/org.matrix.msc3916/media/`. It does this when
`/versions` names `org.matrix.msc3916.stable`. Releases before v0.1.7 serve
only `/_matrix/client/v1/media/`, so each request gets a 404.

To check, request one image at each prefix with an access token:

```sh
for prefix in v1 unstable/org.matrix.msc3916; do
  curl -s -o /dev/null -w "%{http_code} $prefix\n" \
    -H "Authorization: Bearer $TOKEN" \
    "https://matrix.example.org/_matrix/client/$prefix/media/thumbnail/matrix.org/MEDIA_ID?width=96&height=96"
done
```

A 200 for `v1` and a 404 for the unstable prefix is this cause. Upgrade to
v0.1.7 or later. On an older release, rewrite the prefix in the proxy.
This is the Caddy form:

```caddyfile
@msc3916 path_regexp msc3916 ^/_matrix/client/unstable/org\.matrix\.msc3916/media/(.*)$
rewrite @msc3916 /_matrix/client/v1/media/{re.msc3916.1}
```

### A remote file is in the cache with zero bytes

Some servers send a `Location` header in place of the file. Beeper does
this for avatars. Releases before v0.1.5 kept the empty part as the file.
Such a file has a size of zero and the type `application/octet-stream`.
v0.1.5 gets these files again when a client asks for them.

### A remote image has the type `application/octet-stream`

The object store of some servers sends no image type. The thumbnail route
then answers `M_UNSUPPORTED: no thumbnails for application/octet-stream`.
From v0.1.6, Spindle reads the first bytes of the file to find the type.

### A remote server does not answer

The thumbnail answers 404 with `did not yield` after about 30 seconds. The
other server is down. Spindle cannot fix this.

## A room shows no members

The room list is correct, but the member list stays empty. The member
avatars do not show. This occurs after a join to a large room.

Such a join is partial (MSC3706). Later, the server gets the list of
all the members. Until then, `/members` and `/joined_members` do not answer. To
check, look for this line in the log:

```text
cannot resync a partial-state room yet: ...
```

The text after the colon gives the cause. Releases before v0.1.6 stop on
one member event with a bad signature. They also stop when the room's server
refuses one of its auth events with a 403. v0.1.6 leaves out those member
events and completes the resync. This line shows the count:

```text
resync leaves out member events that do not verify ... dropped=3
```

## Find what a client asks for

The metrics of Spindle count the requests for each route. A request that no
route matches has the route label `unmatched`. To see the path, log the
requests in the proxy. Do not log the headers or the access token. This is
the Caddy form:

```caddyfile
log {
	output file /data/access.log
	format filter {
		wrap json
		fields {
			request>headers delete
			resp_headers delete
			request>uri query {
				delete access_token
			}
		}
	}
}
```

Write the log to a file. If the Docker log file of the proxy is gone,
`docker logs` shows no new lines.

Docker mounts a single file by its inode. `sed -i` and most editors write
a new file, so the container continues to read the old one. Write the file
in place, or restart the container.

## Make a test account when registration is closed

With `require_token = true`, a new account needs a registration token.
An admin can make one with an access token. Without an admin token, do these steps:

1. Add `shared_secret = "<random>"` to `[registration]` and restart.
2. Register the account through `/_synapse/admin/v1/register`. The MAC is
   the Synapse form: HMAC-SHA1 of the nonce, user, password and
   `notadmin`, separated by NUL bytes.
3. Remove the secret and restart. The route then answers 404.

The secret can make admin accounts. Do not leave it in the file.

## A release does not tag

`release.yml` tags `main` only when every check on that commit is
complete. The Matrix compliance suite takes about an hour. A dispatch
before then logs one of these lines and builds nothing:

```text
CI is still running on <sha>; not releasing it yet.
The Rust quality gate has not passed on <sha>; not releasing it.
```

Wait for all the checks on the commit, then dispatch again.
