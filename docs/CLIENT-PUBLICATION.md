# Client Publication in 0.23.0

The public URI remains `out/<name>/client/vless-uri.txt`, with unchanged URI
bytes for an unchanged deployment. `client` now selects a completed generation
under `.client-generations/generation-<id>`. Generated files have a private hash
manifest and are validated against the rendered bytes after operator-file copy.

## Guarantees and Limits

- Subsequent POSIX publication replaces one symlink using `os.replace`.
- Subsequent Windows publication updates one existing NTFS junction using
  `FSCTL_SET_REPARSE_POINT` with the same `IO_REPARSE_TAG_MOUNT_POINT` tag. It
  never deletes the current junction before setting the new target.
- Native temporary-directory tests exercised Windows build 26200, local NTFS,
  without elevation, and Linux under WSL2. Repeated switches, concurrent pinned
  reads, process termination, open-file retention, and restart recovery passed.
- This is not a guarantee for every Windows/filesystem/filter combination.
  Windows publication rejects non-NTFS and network paths. OneDrive replication,
  cloud placeholders, ReFS, SMB, and other unqualified filesystems are not
  covered by the temporary local-NTFS tests.
- File and directory flushing is explicit. Successful flushing and process-kill
  tests are not evidence of power-loss durability. No VM power-cut qualification
  was performed, and this release must not advertise that stronger guarantee.

Microsoft documents same-tag modification, not an explicit portable atomicity
or power-loss guarantee for this IOCTL:
[reparse operations](https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-point-operations),
[FSCTL_SET_REPARSE_POINT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-set-reparse-point).
Linux documents atomic name replacement and separate directory synchronization:
[rename](https://man7.org/linux/man-pages/man2/rename.2.html),
[fsync](https://man7.org/linux/man-pages/man2/fsync.2.html).

## First Migration

The first migration from a normal `.22.8` directory is **recoverable, not atomic**
on either implementation. The Windows kernel rejects setting a junction on a
nonempty directory. The installer persists a journal, renames the old directory
to `.client-legacy-<id>`, adopts route state, then activates a prepared pointer.
There is a missing-path window between rename and activation. First migration
requires quiescent consumers and no running legacy route helper; do not start
an old helper during or after migration.

If the publisher dies in that window, `client_artifact_snapshot` reads the
journal-selected retained legacy directory and the original deployment-root
`NEXT-STEPS.txt`, without repairing output. A raw external path reader can see
the missing path. The next publisher reconciles the journal under the existing
publication lock and restores the legacy path or accepts the completed new
generation according to the actual pointer, not a process-local commit flag.
Incomplete recovery preserves the journal and backup and fails closed.

Linux `renameat2(RENAME_EXCHANGE)` can exchange a directory and a symlink, but
this implementation does not use it or claim atomic first-time migration.

## Readers and Operator Data

Opening two files through `client` on opposite sides of a switch can mix
generations even when the pointer operation is atomic. Multi-file readers use
`client_artifact_snapshot`, then finish reading the pinned paths. The artifact
audit and primary-URI verifier use this path. Clipboard output reads just one
URI; displayed artifact paths remain stable public paths.

Authoritative instructions are `client/NEXT-STEPS.txt` in the same generation.
Their artifact paths identify that immutable generation. The deployment-root
`NEXT-STEPS.txt` becomes a constant location notice, not a separately committed
copy of generation instructions.

Route ownership JSON and its lock live in `.client-state`, outside generations.
First migration preserves the original state bytes; conflicting existing stable
state is not overwritten. Unknown operator files/directories are preserved by
copy; links are rejected without modifying their targets. Arbitrary concurrent
operator edits are not supported, although changes detected during copy abort
publication. Windows exclusions are case-insensitive, and rendered-file hashes
are checked again after copy.

`client_publication.rollback` republishes a retained generation's generated
bytes together with the latest operator files. It does not restore an old route
ownership journal. This local API is not a distributed transaction with server
installation/rollback; the install controller must choose when to publish or
restore the corresponding client generation.

## Retention and Maintenance

An unchanged render validates and reuses the selected generation without a
pointer switch or additional storage, even at the retention limit. A retired
entry, including a dangling link, still requires a new clean generation.

There is no automatic deletion while readers might hold pinned paths. Retained
storage is bounded to 32 generation-directory entries and 32 MiB of rendered
and copied file data per generation, plus metadata and filesystem overhead.
Failed staged generations count toward the limit. Existing retained legacy
data is preserved separately. At the limit publication fails before creating
another generation and leaves the current client usable.

Explicit generation cleanup is deferred maintenance, not silent all-history
retention. Before cleanup, quiesce publishers, readers, and helpers; reconcile
any recovery journal; identify the active pointer and required rollback
generations; remove only unreferenced owned generation directories. Do not
follow reparse points, delete `.client-state`, or remove the retained legacy
directory without separately approving disposal of its operator data. The
existing whole-output cleanup command is not generation garbage collection.
