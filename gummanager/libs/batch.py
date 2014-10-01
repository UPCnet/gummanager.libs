def read_csv(filename):
    content = open(filename).read()
    items = []
    for line in content.split('\n'):
        row = []
        for col in line.split(','):
            row.append(col.strip())
        row_empty = len([col for col in row if col]) == 0
        if not row_empty:
            items.append(row)
    return items
