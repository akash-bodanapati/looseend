def normalize(values):  # expect: SLOP003
    total = sum(values) or 1
    scaled = [v / total for v in values]
    rounded = [round(v, 4) for v in scaled]
    clipped = [min(v, 1.0) for v in rounded]
    return clipped
