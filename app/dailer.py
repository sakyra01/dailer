from modules.banner import print_banner
from modules.picker import full_scan, remove_tags, partial_scan, scan_last
from modules.cisa import cisa_db
from modules.last_option_enum import date_calculation
import argparse


print_banner()
ap = argparse.ArgumentParser(
                    prog='Dailer',
                    description='Vulnerability management framework DefectDojo')

ap.add_argument("-a", "--all", action="store_true", help="Scan all active findings and add tags")
ap.add_argument("-pa", "--partial", action="store_true",
                help="Scan findings only with CVE for last 3 years and update tags")
ap.add_argument("-l", "--last", nargs="?", const=0, type=int, action="store",
                help="Scan findings for last days, If you use --last without argument the default value is 0 (today)")
ap.add_argument("-rm", "--remove_tags", action="store_true", help="Remove all tags from findings")


subparser = ap.add_subparsers(dest='sub_flag', help='Add sub flag to extra working')
sub_flag_report = subparser.add_parser("report", help="Add report about critical vulnerabilities")
subparser.required = False
args = vars(ap.parse_args())
report_flag = False


if args['sub_flag'] == 'report':
    report_flag = True


if args['all']:
    cisa_db()
    full_scan(report_flag)


if args['partial']:
    cisa_db()
    partial_scan(report_flag)


if args['last'] is not None:
    last_days = args['last']
    date_list = date_calculation(last_days)
    cisa_db()
    scan_last(date_list, report_flag)


if args['remove_tags']:
    remove_tags(report_flag)

