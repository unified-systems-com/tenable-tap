"""Shared test scaffolding for the tenable plugin's suite."""


def dimension_view(entity) -> dict:
    """An entity's dimensions as ``{name: value}``, whichever way the grid under test stores them.

    A grid from tap 0.3.4 or earlier stores that map directly. A later one keys it by Dimension
    node and wraps each value; its own ``view`` turns that back into names and values.
    """
    try:
        from tap_grid.dimension_names import view
    except ImportError:
        return dict(entity.dimensions or {})
    return view(entity.dimensions)


def keyed_by_node() -> bool:
    """Whether the grid under test keys the dimension map by Dimension node id (tap after 0.3.4)."""
    try:
        import tap_grid.dimension_names  # noqa: F401
    except ImportError:
        return False
    return True
