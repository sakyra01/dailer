from .connections import get_cisa_cve, logger, timestamp


def cisa_update_checker(permission):
    with open('cisa/cisa_list', 'r') as f:
        first_line = f.readline()
        if timestamp in first_line:
            permission = False
    f.close()
    return permission


def cisa_db():
    perm = True
    permission_to_update = cisa_update_checker(perm)

    if permission_to_update is True:

        with open('cisa/cisa_list', 'w') as f:
            cisa_cve_list = get_cisa_cve()
            f.write(f"Last Update - {timestamp}\n")
            for cisa_cve in cisa_cve_list:
                f.write(cisa_cve['cveID'] + '\n')
        f.close()
        logger.info(f"Successfully updated CISA database")
    else:
        logger.info(f"CISA database already updated")


def cisa_checker(cve):

    cisa_tag = None
    with open('cisa/cisa_list', 'r') as f:
        for line in f:
            if cve == line:
                cisa_tag = "cisa"
    f.close()
    return cisa_tag
