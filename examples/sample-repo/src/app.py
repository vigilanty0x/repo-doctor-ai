def load_value(mapping, key):
    # TODO: replace the broad handler with a typed result.
    try:
        return mapping[key]
    except:
        return None

