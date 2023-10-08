import re


def search_cve_in_finding_fields(f_title, f_description, f_references, cve, f_id):

    # Searching cve by regex in fields
    if len(f_title) != 0 and cve is None:
        cve = find_cve_fields(f_title)
    if len(f_description) != 0 and cve is None:
        cve = find_cve_fields(f_description)
    if len(f_references) != 0 and cve is None:
        cve = find_cve_fields(f_references)
    return cve


def find_cve_fields(field):
    catcher = regex(field)
    return catcher


def regex(line):
    new_line = line.split()
    for li in new_line:
        result = re.search(r"CVE-\d{4}-\d{4,7}", li)
        if result is not None:
            return result.group(0)
