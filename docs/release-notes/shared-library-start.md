- Open shared libraries that have no `main` and a zero entry point at their lowest
  known function instead of attempting address zero, which previously reported
  that `0x0` was outside file-backed executable sections and stopped the worker.
  New projects and reopened projects fall back the same way.
