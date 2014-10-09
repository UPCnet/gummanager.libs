import xlrd
import unicodedata


def make_subs(label):
    normalized_label = unicodedata.normalize('NFD', unicode(label)).encode('ascii', errors="ignore")
    if normalized_label in ['usuari', 'usuario', 'user', 'username']:
        return 'username'
    elif normalized_label in ['nom', 'nombre', 'name', 'fullname']:
        return 'fullname'
    elif normalized_label in ['mail', 'e-mail', 'email', 'correu', 'correo', 'correuelectronic', 'correoelectronico']:
        return 'email'
    elif normalized_label in ['password', 'pass', 'palabraclave', 'paraulaclau', ]:
        return 'password'
    elif normalized_label in ['owners', 'propietarios', 'propietaris']:
        return 'owners'
    elif normalized_label in ['readers', 'lectors', 'lectores']:
        return 'readers'
    elif normalized_label in ['editors', 'editores']:
        return 'editors'
    else:
        return label


def get_field_positions(labels):
    field_map = {}
    labels = [label.replace(' ', '').lower() for label in labels]
    for pos, label in enumerate(labels):
        field_map[pos] = make_subs(label)

    return field_map


def validate_header(rows, required_fields=[], position=0):
    fields = get_field_positions(rows[position])
    fields_ok_count = 0
    if required_fields:
        for req in required_fields:
            if req in fields.values():
                fields_ok_count += 1

    if fields_ok_count == 0 and required_fields:
        raise MissingColumns('Missing column headers on row #{}'.format(position))
    elif fields_ok_count < len(required_fields):
        raise MissingColumns('Missing column(s) or wrong column name(s)')

    return fields


class MissingColumns(Exception):
    """
    """


def is_excel(filename):
    try:
        xlrd.open_workbook(filename)
    except:
        return None
    else:
        return True


def read_xls(xlsfile, required_fields=[]):
    book = xlrd.open_workbook(xlsfile)
    sheets = []
    for sheet in book.sheets():
        rows = [sheet.row_values(rowpos) for rowpos in range(sheet.nrows)]
        sheets.append(rows)
    return sheets


def read_csv(csvfile, required_fields=[]):
    content = open(csvfile).read()
    lines = content.split('\n')
    return lines


def parse_users(rows, required_fields=[]):
    fields = validate_header(rows, required_fields=required_fields)
    users = []

    for rawrow in rows[1:]:
        row = [col.strip() for col in rawrow]
        row_empty = len([col for col in row if col]) == 0
        if not row_empty:
            user = {}
            for fieldpos, fieldname in fields.items():
                user[fieldname] = row[fieldpos]
            users.append(user)

    return users


def parse_subscriptions(rows, required_fields=[]):
    fields = validate_header(rows, required_fields=required_fields, position=1)

    subscriptions = {}
    for rawrow in rows[2:]:
        row = [col.strip() for col in rawrow]

        for fieldpos, fieldname in fields.items():
            username = row[fieldpos]
            if username:
                subscriptions.setdefault(fieldname, []).append(username)

    return subscriptions


def read_users_file(filename, required_fields=[]):
    if is_excel(filename):
        rows = read_xls(filename)[0]
    else:
        rows = read_csv(filename)

    try:
        users = parse_users(rows, required_fields)
    except MissingColumns as exc:
        raise exc
    except Exception as exc:
        raise exc
    return users


def read_subscriptions_file(filename, required_fields=[]):
    if is_excel(filename):
        sheets = read_xls(filename)
    else:
        raise Exception('Not an excel file')

    communities = []
    for rows in sheets:
        try:
            community_url = rows[0][1].strip()
            users = parse_subscriptions(rows, required_fields)
        except MissingColumns as exc:
            raise exc
        except Exception as exc:
            raise exc
        communities.append({
            "url": community_url,
            "owners": users.get('owners', []),
            "readers": users.get('readers', []),
            "editors": users.get('editors', []),
        })
    return communities
