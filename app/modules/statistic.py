def make_report(arg, cve_error_counter, base_critical_counter, cisa_counter, epss_critical_counter,
                exploitability_critical_counter, updated_tags, impact_score_counter):

    message = f"Program working option {arg}\n" \
              f"CVE didn't found in ({cve_error_counter}) findings\n" \
              f"Findings with CVE and base_critical tags ({base_critical_counter})\n" \
              f"Findings with CVE which have been found in CISA Database ({cisa_counter})\n" \
              f"Findings with CVE and epss_critical tags ({epss_critical_counter})\n" \
              f"Findings with CVE and exploitability_critical tags ({exploitability_critical_counter})\n" \
              f"Findings with CVE and impact_critical tags ({impact_score_counter})\n" \
              f"Findings witch CVE where have been updated tags ({updated_tags})\n" \
              f"More information in attachment - logfile.log\n" \

    return message


def statistic_report(arg):
    if type(arg) == list:
        days = len(arg)
        if days == 1:
            arg = f"--last for last day"
        else:
            arg = f"--last for last {days} days"

    cve_error_counter = 0
    base_critical_counter = 0
    cisa_counter = 0
    epss_critical_counter = 0
    exploitability_critical_counter = 0
    updated_tags_count = 0
    impact_score_counter = 0

    with open('logs/logfile.log', 'r') as log_file:
        for line in log_file:
            if "Found new tags" in line:
                if "exploitability_critical" in line:
                    exploitability_critical_counter += 1
                if "cisa" in line:
                    cisa_counter += 1
                if "epss_critical" in line:
                    epss_critical_counter += 1
                if "base_critical" in line:
                    base_critical_counter += 1
                if "impact_critical" in line:
                    impact_score_counter += 1

            if "Updated new tags" in line:
                updated_tags_count += 0

            if "CVE didn't find in finding" in line:
                cve_error_counter += 1

    log_file.close()
    message = make_report(arg, cve_error_counter, base_critical_counter, cisa_counter, epss_critical_counter,
                exploitability_critical_counter, updated_tags_count, impact_score_counter)
    return message
