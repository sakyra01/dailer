from .nist import nist
from .cve_search import search_cve_in_finding_fields
from .connections import logger, check_connection_pedb, get_findings_data, year, statistic_message, send_alerts_messages
from .exploit_db import exploit_db
from .rm_tags import rm_tags
from .cisa import cisa_checker
from .epss import epss_checker
from .updating_tags import update_tags
from .alerts_options import alerting_checker, first_writer_alert, make_alert_report
from .statistic import statistic_report
import re


# Function which calling from piker program. Here program add arg of option and run necessary functional
def balancer(arg, report_flag):
    first_writer_alert()    # Rewrite alert file every time we start program

    # Start script
    if type(arg) == list:
        logger.info("===START script with --last option===")
    else:
        logger.info(f"===START script with {arg} option===")

    # Update DB exploit-db from https://gitlab.com/exploit-database/exploitdb + check connection to python library pyDb
    if arg != "--remove_tags":
        check_connection_pedb()
        logger.info("Exploit-db local DB updated successfully")

    # Requests with limit&offset step by 1000 findings
    offset = 0
    for step in range(10000):
        content = get_findings_data(offset)  # Get response of findings from DefectDojo

        if content != 0:
            enumeration(content, arg)  # Run main function
            offset += 1000  # Step for offset in loop
            step += 1  # Loop for pagination of page
        else:
            break

    if report_flag is True:
        # Send statistic information in Rocketchat
        message = statistic_report(arg)
        statistic_message(message)

        # Send alert information in Rocketchat
        alert_message = make_alert_report()
        if alert_message is not None:
            send_alerts_messages(alert_message)

    # Stop script
    logger.info(f"===STOP script===")
    return


def enumeration(results, arg):
    # Enumerate findings one by one in data list + Declaration main fields from findings
    for finding in range(len(results)):
        # Empty list of our future list of tags
        list_of_tags = []
        f_id = results[finding]['id']
        finding_status = results[finding]['display_status']
        f_tags = results[finding]['tags']
        f_scanner_id = results[finding]['found_by']
        verified_status = results[finding]['verified']

        if 'Active' in finding_status:
            f_title = results[finding]['title']
            f_description = results[finding]['description']
            f_references = results[finding]['references']
            f_cve = results[finding]['vulnerability_ids']
            f_date = results[finding]['date']

            if arg == "--all":
                cve = cve_contains_checker(f_cve, f_title, f_description, f_references, f_id)
                option_worker(cve, f_id, list_of_tags)

            elif arg == "--partial":
                cve = cve_contains_checker(f_cve, f_title, f_description, f_references, f_id)
                partial_status = cve_year_checker(cve)   # Check CVE by year for partial option
                # Condition of work option partial, CVE for last 3 years
                if partial_status is True:
                    option_worker(cve, f_id, list_of_tags)

            # Condition to use --last option. Only --last option has list object
            elif type(arg) == list:
                status = cve_date_compare_for_last_option(arg, f_date)
                if status is True:
                    cve = cve_contains_checker(f_cve, f_title, f_description, f_references, f_id)
                    option_worker(cve, f_id, list_of_tags)

            elif arg == "--remove_tags":
                rm_tags(f_tags, f_id)

        # Post-processing - modify tags list and send new tags to finding
        if len(list_of_tags) != 0:
            update_tags(f_tags, list_of_tags, f_id)
            if verified_status is True:
                alerting_checker(list_of_tags, f_scanner_id, f_id)


def option_worker(cve, finding_id, list_of_tags):
    if cve is not None:
        nist_tag_list = nist(cve)
        exploit_db_tag = exploit_db(cve, finding_id)
        cisa_tag = cisa_checker(cve)
        epss_tag = epss_checker(cve)

        # Condition to add unNone values to list of tags
        if nist_tag_list is not None:
            for nist_tag in nist_tag_list:
                list_of_tags.append(nist_tag)
        if exploit_db_tag is not None:
            list_of_tags.append(exploit_db_tag)
        if cisa_tag is not None:
            list_of_tags.append(cisa_tag)
        if epss_tag is not None:
            list_of_tags.append(epss_tag)

    # Here we are statistic that finding didn't have CVE value at all
    else:
        logger.info(f"CVE didn't find in finding-{finding_id}")


def cve_contains_checker(f_cve, f_title, f_description, f_references, f_id):
    cve = None
    if len(f_cve) != 0:
        cve = f_cve[0]['vulnerability_id']

    elif len(f_cve) == 0:
        cve = search_cve_in_finding_fields(f_title, f_description, f_references, cve, f_id)
    return cve


def cve_year_checker(cve_id):
    pattern = r"\d{4}"
    matches = re.findall(pattern, cve_id)

    if matches:
        cve_year = matches[0]
        compare_year = int(year) - int(cve_year)
        if compare_year <= 3:
            return True
        else:
            return False
    else:
        return False


def cve_date_compare_for_last_option(args_list, f_date):
    status = False

    for arg in args_list:
        if f_date == arg:
            status = True

    return status
