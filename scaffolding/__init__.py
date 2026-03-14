"""
Non-production scaffolding and test-only helpers.

This package holds components that exist solely to support tests and developer
smoke flows. They are intentionally excluded from the installable Olympus
package to avoid advertising unfinished features or test wiring as production
APIs.
"""

__all__ = ["app_testonly", "view_change"]
