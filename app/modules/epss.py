from .connections import get_epss


def epss_checker(cve):
    epss_tag = None
    epss_data = get_epss(cve)
    if len(epss_data) != 0:
        epss_data_value = epss_data["data"]
        if len(epss_data_value) != 0:
            epss_number = epss_data_value[0]["epss"]
            epss = float(epss_number) * 100

            if 0 <= epss <= 25:
                epss_tag = "epss_low"
            elif 26 <= epss <= 50:
                epss_tag = "epss_medium"
            elif 51 <= epss <= 75:
                epss_tag = "epss_high"
            elif 76 <= epss <= 100:
                epss_tag = "epss_critical"
    return epss_tag
