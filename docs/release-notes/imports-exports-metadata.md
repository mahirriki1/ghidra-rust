- Add bounded worker metadata for declared imports and exports, including library
  grouping, raw and demangled names, and exact validated slot/code/data locations.
  Symbol Tree browsing and navigation are pending desktop integration.
- Preserve PE aliases, ordinal-only and data exports, forwarders, and conventional
  RVA-form delay imports without adding delay imports to analysis registration.
  ELF ownership uses symbol-version requirements; unowned declarations remain
  unknown. Mach-O uses nlist declarations, library ordinals and indirect symbols.
- Bind metadata pages to the immutable image and metadata policy, enforce count,
  text, encoded-page and parser-work limits, and reject conflicting or unmapped
  locations. Metadata is rebuilt from the verified image rather than saved into
  projects; unsupported dyld binding, chained fixups and export tries remain
  explicit coverage gaps.
