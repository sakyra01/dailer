from .enum import balancer


report_key = False


def full_scan(report_flag):
    arg = '--all'
    balancer(arg, report_flag)


def partial_scan(report_flag):
    arg = '--partial'
    balancer(arg, report_flag)


def remove_tags(report_flag):
    arg = '--remove_tags'
    balancer(arg, report_flag)


def scan_last(date_list, report_flag):
    balancer(date_list, report_flag)
