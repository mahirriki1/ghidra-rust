- The Listing now opens in the **Program** scope, listing the whole program in
  address order. **Function** stays available in the Listing's title row. The
  scope you choose is kept while you open other binaries and projects in the
  same session; each launch starts in **Program**.
- Fixed: reopening a project saved with a `??` byte row selected inside a code
  section no longer opens that address as a guessed function. Reopening opens
  a function only at a known function entry or an instruction of the saved
  function. Any other saved address lands on its exact Program row over the
  saved function, with the row's bytes expanded as Go To would.
- Projects now store the exact selected Listing address, including data rows
  and `??` bytes, instead of only code addresses. While Hex is shown, the
  Listing selection it departed from is saved, as before.
- When a project's saved function results cannot be used (for example after
  an engine update), reopening opens the function that was displayed, as long
  as it is still a known function, and otherwise the opening location. In
  the Program scope the cursor then lands on the saved row, waiting for that
  function's body if the row lies inside it.
- In the **Function** scope, reopening opens the same function as the
  Program scope and selects its entry instead of moving to a row that the
  Function scope cannot show.
- The project format is unchanged (version 4), and existing projects still
  open. Releases before this one still open a saved executable address that
  is not a function entry as a function of its own; this was already possible
  with projects saved by releases that show `??` byte rows in code sections.
