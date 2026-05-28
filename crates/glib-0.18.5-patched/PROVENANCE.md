# glib-0.18.5-patched — vendoring provenance

Targeted backport of upstream [gtk-rs/gtk-rs-core#1343](https://github.com/gtk-rs/gtk-rs-core/pull/1343)
onto the `glib` 0.18.5 release that Tauri's webkit2gtk-4.1 / GTK 0.18
stack pins. Closes Dependabot alert
[GHSA-wrw7-89jp-8q8g](https://github.com/advisories/GHSA-wrw7-89jp-8q8g)
on the Linux bundle without waiting for Tauri to ship a webkit2gtk
binding compatible with glib ≥ 0.20.

## Upstream pin

| Field            | Value |
| ---------------- | ----- |
| Upstream repo    | `https://github.com/gtk-rs/gtk-rs-core` (crate `glib/`) |
| Upstream version | `0.18.5` (latest 0.18.x release) |
| Source artifact  | `https://static.crates.io/crates/glib/glib-0.18.5.crate` |
| Fetched on       | 2026-05-28 (see commit history) |
| Fix backported   | gtk-rs/gtk-rs-core#1343 — `VariantStrIter::impl_get` mutability fix |

The vendored tree is **byte-identical to the published `glib-0.18.5`
crate** with one exception: the 2-line patch below in
`src/variant_iter.rs::impl_get`. `Cargo.toml` is the registry-normalized
copy (cargo rewrites `path` deps to crates.io deps on publish) and is
left unmodified.

## The patch

GHSA-wrw7-89jp-8q8g: `VariantStrIter::impl_get` passed an **immutable**
reference `&p` to `glib_sys::g_variant_get_child`, which writes the
child string pointer back through that argument. The compiler is then
free to DCE the unsound write, producing a NULL dereference downstream.
Fix is one keyword + one `mut`:

```diff
--- a/glib/src/variant_iter.rs
+++ b/glib/src/variant_iter.rs
@@ -118,12 +118,12 @@ impl<'a> VariantStrIter<'a> {
     fn impl_get(&self, i: usize) -> &'a str {
         unsafe {
-            let p: *mut libc::c_char = std::ptr::null_mut();
+            let mut p: *mut libc::c_char = std::ptr::null_mut();
             let s = b"&s\0";
             ffi::g_variant_get_child(
                 self.variant.to_glib_none().0,
                 i,
                 s as *const u8 as *const _,
-                &p,
+                &mut p,
                 std::ptr::null::<i8>(),
             );
             let p = std::ffi::CStr::from_ptr(p);
```

Source-level comments inside `variant_iter.rs` annotate the change with
the GHSA / upstream-PR references so a future reader can re-derive the
provenance without leaving the file.

## Retire-when condition

Drop this vendored crate **and** the `[patch.crates-io] glib = …` entry
in the workspace `Cargo.toml` as soon as either:

1. Tauri ships a webkit2gtk binding using `glib ≥ 0.20.0` (cleanest —
   removes the 0.18 line from the dep tree entirely), or
2. gtk-rs publishes a `glib 0.18.6` containing the upstream fix
   (a backport release would supersede this in-tree copy).

Track via Tauri release notes + the `glib` crates.io release feed.

## Verifying the backport locally

```bash
# 1. Confirm the [patch] is winning the resolve.
cargo tree -p glib | head -1
#   expected: glib v0.18.5 (/.../crates/glib-0.18.5-patched)

# 2. Confirm the fix is in place.
grep -nE 'let mut p|&mut p,' crates/glib-0.18.5-patched/src/variant_iter.rs
#   expected: line 130 (let mut p) + line 135 (&mut p,)

# 3. Confirm the GHSA no longer surfaces.
cargo audit            # GHSA-wrw7-89jp-8q8g should be absent
```
