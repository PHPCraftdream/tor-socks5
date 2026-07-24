BREAKING: All TorClient constructors now return Arc<TorClient>.
BREAKING: TorClient no longer implements Clone.
BREAKING: `set_stream_prefs` has been removed.
BREAKING: `clone_with_prefs` has been renamed to `with_prefs`.
BREAKING: The `use_obsolete_software` options has been removed.
   (This is breaking for Rust code that constructed that option,
   but not for .toml files, where obsolete options are ignored.)
BREAKING, experimental-api: Several experimental-api methods are now fallible.

