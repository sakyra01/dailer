from .connections import nist_connection


cvssv31 = 'cvssMetricV31'
cvssv30 = 'cvssMetricV30'


def nist(cve_id):
    nist_data = nist_connection(cve_id)
    if len(nist_data["vulnerabilities"]) != 0:
        nvd_short = nist_data["vulnerabilities"][0]["cve"]["metrics"]

        # Here we are trying figure out which cvss version using by nvd nist
        if cvssv30 in nvd_short:
            nvd_tag_list = nvd_nist_searcher(cvssv30, nvd_short)
            return nvd_tag_list

        elif cvssv31 in nvd_short:
            nvd_tag_list = nvd_nist_searcher(cvssv31, nvd_short)
            return nvd_tag_list
    else:
        return None


def nvd_nist_searcher(cvss, nvd_sh):
    nist_exploit_score = nvd_sh[cvss][0]["exploitabilityScore"]
    nist_impact_score = nvd_sh[cvss][0]["impactScore"]
    nist_attack_vector = nvd_sh[cvss][0]["cvssData"]["attackVector"]
    nist_base_severity = nvd_sh[cvss][0]["cvssData"]["baseSeverity"]
    nist_attack_complexity = nvd_sh[cvss][0]["cvssData"]['attackComplexity']
    nist_privileges_required = nvd_sh[cvss][0]["cvssData"]['privilegesRequired']

    nist_tag_list = nist_tagging(nist_exploit_score, nist_impact_score, nist_attack_vector, nist_base_severity,
                                 nist_attack_complexity, nist_privileges_required)

    return nist_tag_list


def nist_tagging(nist_exploit_score, nist_impact_score, nist_attack_vector, nist_base_severity, nist_attack_complexity, nist_privileges_required):
    n_av = n_ac = n_is = n_bs = n_es = pr = None

    if "none" in nist_privileges_required.lower():
        pr = "pr_n"
    elif "low" in nist_privileges_required.lower():
        pr = "pr_l"
    elif "high" in nist_privileges_required.lower():
        pr = "pr_h"

    # Nist attack vector
    if "network" in nist_attack_vector.lower():
        n_av = "av_n"
    elif "local" in nist_attack_vector.lower():
        n_av = "av_l"
    elif "physical" in nist_attack_vector.lower():
        n_av = "av_p"
    elif "adjacent" in nist_attack_vector.lower():
        n_av = "av_a"

    # Nist attack complexity
    if "low" in nist_attack_complexity.lower():
        n_ac = "ac_l"
    elif "high" in nist_attack_complexity.lower():
        n_ac = "ac_h"

    # Nist base severity
    if "none" in nist_base_severity.lower():
        n_bs = "base_none"
    if "low" in nist_base_severity.lower():
        n_bs = "base_low"
    if "medium" in nist_base_severity.lower():
        n_bs = "base_medium"
    if "high" in nist_base_severity.lower():
        n_bs = "base_high"
    if "critical" in nist_base_severity.lower():
        n_bs = "base_critical"

    # Nist impact score
    if nist_impact_score == 0.0:
        n_is = "impact_none"
    elif 0.1 <= nist_impact_score <= 3.9:
        n_is = "impact_low"
    elif 4.0 <= nist_impact_score <= 6.9:
        n_is = "impact_medium"
    elif 7.0 <= nist_impact_score <= 8.9:
        n_is = "impact_high"
    elif 9.0 <= nist_impact_score <= 10.0:
        n_is = "impact_critical"

    # Nist exploit score
    if nist_exploit_score == 0.0:
        n_es = "exploitability_none"
    elif 0.1 <= nist_exploit_score <= 3.9:
        n_es = "exploitability_low"
    elif 4.0 <= nist_exploit_score <= 6.9:
        n_es = "exploitability_medium"
    elif 7.0 <= nist_exploit_score <= 8.9:
        n_es = "exploitability_high"
    elif 9.0 <= nist_exploit_score <= 10.0:
        n_es = "exploitability_critical"

    nist_tag_list = [n_av, n_ac, n_is, n_bs, n_es, pr]
    return nist_tag_list
