from .connections import get_products, url


def alerting_checker(list_of_tags, f_scanner_id, finding_id):

    allow_scanners_list = [133, 113, 127, 57, 164, 56]
    finding_scanner_id = f_scanner_id[0]
    current_scanner_name = find_scaner_namez(finding_scanner_id)

    # Loop of conditions for right alerts
    for allow_scanner_id in allow_scanners_list:
        if finding_scanner_id == allow_scanner_id:

            # (OR) Condition for tags: epss_critical, exploit-db, cisa, exploitability_critical values.
            if ("epss_critical" in list_of_tags) or ("exploit-db" in list_of_tags) or ("cisa" in list_of_tags) or ("exploitability_critical" in list_of_tags):
                product_checker(finding_id, current_scanner_name, list_of_tags)
            # (AND) Condition for tags: av_n, ac_l, pr_n, base_critical
            elif ("av_n" in list_of_tags) and ("ac_l" in list_of_tags) and ("pr_n" in list_of_tags) and ("base_critical" in list_of_tags):
                product_checker(finding_id, current_scanner_name, list_of_tags)

        if finding_scanner_id == 61:
            product = get_products(finding_id)
            severity = product["severity"]
            if "Critical" in severity:
                message = f"Found Critical vulnerability for finding - {url}{finding_id}. Scanner - ZAP Scan. Tags-{list_of_tags}\n"
                vulnerability_list(message)

        if finding_scanner_id == 140:
            message = f"Found vulnerability for finding - {url}{finding_id}. Scanner - Trufflehog. Tags-{list_of_tags}\n"
            vulnerability_list(message)
    return


def find_scaner_namez(finding_scanner_id):
    scanner_dict = {
        133:    'AuditJS Scan',
        113:    'Nessus Scan',
        127:    'Nessus WAS Scan',
        57:     'Harbor Vulnerability Scan',
        164:    'Trivy Operator Scan',
        56:     'Trivy Scan',
        61:     'ZAP Scan',
        140:    'Trufflehog Scan'
    }

    # Here we figure out the name of scanner by scanner ID. We need current name of scanner to add it in alert message.
    for scanner_dict_id in scanner_dict:
        if scanner_dict_id == finding_scanner_id:
            scanner_name = scanner_dict[scanner_dict_id]
            return scanner_name
        return None


def product_checker(finding_id, current_scanner_name, list_of_tags):
    data = get_products(finding_id)
    if len(data) > 2:
        product_name = data['related_fields']['test']['engagement']['product']['name']
        product_prod_type_name = data['related_fields']['test']['engagement']['product']['prod_type']['name']

        if (product_name == 'perimeter EXT X5D') or (product_prod_type_name == 'WEB applications EXT'):
            message = f"Found Critical vulnerability for finding - {url}{finding_id}. Scanner - {current_scanner_name}. Tags-{list_of_tags}\n"
            vulnerability_list(message)
            return


def first_writer_alert():
    with open('logs/alerts_list', 'w') as alert_file:
        alert_file.write("Information about (Critical;Verified) Vulns:\n")
    alert_file.close()


def vulnerability_list(message):
    with open('logs/alerts_list', 'a') as alert_file:
        alert_file.write(message)
    alert_file.close()
    return


def make_alert_report():
    alert_message = ""
    vulns_counter = 0
    with open('logs/alerts_list', 'r') as alert_file:
        for line in alert_file:
            vulns_counter += 1
            new_line = line.strip()
            alert_message += f"{new_line}\n"
    alert_file.close()
    if vulns_counter == 1:
        alert_message = None
    alert_file.close()
    return alert_message




