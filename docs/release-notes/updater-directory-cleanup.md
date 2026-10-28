- Successful Windows updates remove the empty staging directory through its
  retained, identity-checked directory handle. Renaming that directory and placing
  an unrelated empty folder or junction at its old path cannot redirect cleanup.
- Directory cleanup refuses nonempty folders and never recursively removes files.
