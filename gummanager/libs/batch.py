import xlrd
import unicodedata


def make_subs(label):
    normalized_label = unicodedata.normalize('NFD', unicode(label)).encode('ascii', errors="ignore")
    if normalized_label in ['usuari', 'usuario', 'user', 'username']:
        return 'username'
    elif normalized_label in ['nom', 'nombre', 'name', 'fullname']:
        return 'fullname'
    elif normalized_label in ['mail', 'e-mail', 'email', 'correu', 'correo']:
        return 'email'
    elif normalized_label in ['password', 'pass', 'palabraclave', 'paraulaclau', 'correuelectronic', 'correoelectronico']:
        return 'password'
    else:
        return label


def get_field_positions(labels):
    field_map = {}
    labels = [label.replace(' ', '').lower() for label in labels]
    for pos, label in enumerate(labels):
        field_map[pos] = make_subs(label)

    return field_map


class MissingColumns(Exception):
    pass


class NotAnExcel(Exception):
    pass


def read_xls(xlsfile, required_fields=[]):
    try:
        book = xlrd.open_workbook(xlsfile)
    except:
        raise NotAnExcel()

    sheet = book.sheets()[0]
    fields = get_field_positions(sheet.row_values(0))
    fields_ok_count = 0
    if required_fields:
        for req in required_fields:
            if req in fields.values():
                fields_ok_count += 1

    if fields_ok_count == 0:
        raise MissingColumns('Missing column headers on row #0')
    elif fields_ok_count < len(required_fields):
        raise MissingColumns('Missing column(s) or wrong column name(s)')

    users = []

    for rowpos in range(1, sheet.nrows):
        row = row = [col.strip() for col in sheet.row_values(rowpos)]
        row_empty = len([col for col in row if col.strip()]) == 0
        if not row_empty:
            user = {}
            for fieldpos, fieldname in fields.items():
                user[fieldname] = row[fieldpos]
            users.append(user)

    return users


def read_csv(csvfile, required_fields=[]):
    content = open(csvfile).read()
    lines = content.split('\n')

    fields = get_field_positions(lines[0].split(','))
    fields_ok_count = 0
    if required_fields:
        for req in required_fields:
            if req in fields.values():
                fields_ok_count += 1

    if fields_ok_count == 0 and required_fields:
        raise MissingColumns('Missing column headers on row #0')
    elif fields_ok_count < len(required_fields):
        raise MissingColumns('Missing column(s) or wrong column name(s)')

    users = []

    for line in lines[1:]:
        row = [col.strip() for col in line.split(',')]
        row_empty = len([col for col in row if col]) == 0
        if not row_empty:
            user = {}
            for fieldpos, fieldname in fields.items():
                user[fieldname] = row[fieldpos]
            users.append(user)

    return users


def read_users_file(filename, required_fields=[]):
    # Try to read as xls
    try:
        users = read_xls(filename, required_fields)
    except MissingColumns as exc:
        raise exc
    except NotAnExcel as exc:
        # Otherwise try to read as csv
        try:
            users = read_csv(filename, required_fields)
        except MissingColumns as exc:
            raise exc
        except:
            return None
    return users
