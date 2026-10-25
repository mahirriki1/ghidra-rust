- Keep analysis progress visible across discovery batches, adoption, setup,
  foreground navigation, and automatic worker recovery, with elapsed time for
  the complete run and the current selected auto-analysis step.
- Show processed/admitted function counts and a solid fill for known-function
  work. Failed and limited attempts count as processed; in-flight work does not.
  The total can grow, so the fill can decrease; it is not whole-program coverage.
- Use animated activity for strings, constants, patterns, setup, adoption, and
  waits. Cancel clears progress immediately; resume starts a fresh clock while
  retaining committed results. Reopening saved analysis does not start progress.
