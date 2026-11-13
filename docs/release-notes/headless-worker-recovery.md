- Headless sessions now survive a stopped worker. A timeout, cancellation,
  transport failure or engine error stops the worker, but completed function
  results, scans, committed discovery and annotations stay available.
  `info`, `annotations` and `save_project` keep working, including after
  permanent cancellation, and embedded projects can still be saved and
  reopened.
- Engine errors from `bytes` and `linkage` are now reported as the new
  `command_failed` code, and the worker keeps running, as on the desktop.
  Other engine errors are reported as `worker_failed` and stop the worker.
- A failed `discover` step keeps its committed evidence. Its seeds are retried
  one at a time and are marked failed after a second failure. The next
  `discover` call starts a replacement worker for the same image. The
  replacement must match the image's identity, hash and section mapping, and
  names and signatures are replayed to it first. A session allows at most
  three replacement workers (the desktop limit); after that, `discover`
  returns `session_closed`.
- Console startup errors now stop and reap the worker before the process exits,
  so an image extracted from an embedded project is no longer left in the
  temporary directory.
- Replies never repeat a request ID. Zero, replayed or non-increasing IDs are
  answered with `"id": null`. A rejected request with a new, larger ID echoes
  that ID and uses it up.
