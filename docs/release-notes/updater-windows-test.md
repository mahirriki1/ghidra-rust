- Fix the updater regression test on Windows by moving the retained executable
  aside before simulating an external replacement. The test continues to require
  rejection of changed executables and analyzed-input hard-link aliases; updater
  installation checks are unchanged.
