# Imported Proxy frontend extensions

The application on Proxy used the 92c3c75 React build plus independently loaded
JS/CSS files. This import preserves those active extensions in public/assets;
they are versioned frontend source, not generated React bundles.

portal-extensions.json records the tags in their original order, loading
attributes, query versions and file hashes. The post HTML hook in vite.config.js
adds the same tags after the compiled entry. Vite copies the public files into
the build. No handwritten changes to a generated index are needed.

The capture includes the detail single-toggle update. The rolled-back
EVENT_DETAIL_SOURCE_AWARE_V1 JSX patch and inactive DEMO_COMPACT_V5 are excluded.

The original React source remains the base application. The extensions still
modify presentation in the browser; some also make authenticated read-only
API requests. Their behavior is retained during this import. A future move
into React components should be reviewed and tested as a separate change.

To modify an extension, edit its source under public/assets, intentionally
update the corresponding hash/tag record, run frontend tests and build, then
run deploy/portal-local/verify_import.py against the build. Changes to execution
order or defer attributes require a separate browser behavior review.
