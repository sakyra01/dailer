def make_report(arg, cve_error_counter, base_critical_counter, cisa_counter, epss_critical_counter,
                exploitability_critical_counter, updated_tags, impact_score_counter, new_tags, list_of_critical_findings):

    if len(list_of_critical_findings) == 0:
        list_of_critical_findings = "No information during scanning"
        message = f"Program working option {arg}\n" \
                  f"1.CVE didn't find in {cve_error_counter} findings\n" \
                  f"2.base_critical tags-{base_critical_counter}\n" \
                  f"3.CVE found in CISA DB-{cisa_counter}\n" \
                  f"4.epss_critical tags-{epss_critical_counter}\n" \
                  f"5.exploitability_critical tags-{exploitability_critical_counter}\n" \
                  f"6.impact_critical tags-{impact_score_counter}\n" \
                  f"7.Updated tags-{updated_tags}\n" \
                  f"8.New tags-{new_tags}\n" \
                  f"-Info about exploits-\n" \
                  f"{list_of_critical_findings}\n" \
                  f"More info in logfile.log\n"

    else:
        message = f"Program working option {arg}\n" \
                  f"1.CVE didn't find in {cve_error_counter} findings\n" \
                  f"2.base_critical tags-{base_critical_counter}\n" \
                  f"3.CVE found in CISA DB-{cisa_counter}\n" \
                  f"4.epss_critical tags-{epss_critical_counter}\n" \
                  f"5.exploitability_critical tags-{exploitability_critical_counter}\n" \
                  f"6.impact_critical tags-{impact_score_counter}\n" \
                  f"7.Updated tags-{updated_tags}\n" \
                  f"8.New tags-{new_tags}\n" \
                  f"-Info about exploits-\n" \
                  f"{', '.join(list_of_critical_findings)}\n" \
                  f"More info in logfile.log\n"
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
    list_of_critical_findings = []
    new_tags = 0

    with open('logs/logfile.log', 'r') as log_file:
        for line in log_file:
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

            if "New tags are the same as old tags" in line:
                updated_tags_count += 1

            if "Add new tags" in line:
                new_tags += 1

            if "CVE didn't find in finding" in line:
                cve_error_counter += 1

            if "Exploit link" in line:
                list_of_critical_findings.append(line)

    log_file.close()
    message = make_report(arg, cve_error_counter, base_critical_counter, cisa_counter, epss_critical_counter,
                exploitability_critical_counter, updated_tags_count, impact_score_counter, new_tags, list_of_critical_findings)
    return message
