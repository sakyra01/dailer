# Dailer framework

<p align="center">
      <img src="app/images/Dailer.png" alt="Image" width="400" />
</p>

[![python version](https://img.shields.io/badge/Python-3.11%2B-brightgreen)](https://www.python.org/downloads/)

# Description
**Dailer is a framework that scans DefectDojo findings in several modes and performs specific actions. Scanning is done using the DefectDojo API.** 

**The main functionality is adding tags to finding files to keep track of vulnerabilities**

![dailer-framework.png](app/images/dailer-framework.png)

## Operating modes ♨️
```console
usage: Dailer [-h] [-a] [-pa] [-l [LAST]] [-rm] {report} ...

Vulnerability management framework DefectDojo

positional arguments:
  {report}              Add sub flag to extra working
    report              Add report about critical vulnerabilities

options:
  -h, --help            show this help message and exit
  -a, --all             Scan all active findings and add tags
  -pa, --partial        Scan findings only with CVE for last 3 years and update tags
  -l [LAST], --last [LAST]
                        Scan findings for last days, If you use --last without argument the default value is 0 (today)
  -rm, --remove_tags    Remove all tags from findings

```
**Example of running the framework:**
```console
$ python3 dailer.py --last 3 report 
// The framework scans findings for the last 3 days with the [--last] flag and the {report} subflag allows you to send a work report to some chat.
```
**About operating modes:**

The framework scans all (Active) findings that are on DefectDojo;
  1. The [--all] flag adds tags to them.
  2. The [--partial] flag checks only CVEs for the last 3 years and adds tags to them.
  3. The [--last + (arg)] flag compares the dates generated by the [--last] and (arg) flags and, if they match, adds tags (arg is the number of last days from the current framework launch date). 
  4. The [--remove_tags] flag removes all tags.

**An issue was found with the DefectDojo API. The API does not accept request parameters, so the program's running time increases exponentially with the number of finds on DefectDojo.**

- [x] **Bug report** was sent to the developers - https://github.com/DefectDojo/django-DefectDojo/issues/8592

## About tags 🏷️
**Tags are added based on the CVE information in each finder.**
  - [x] Information from the NVD database. Tags are added for the following parameters: exploitabilityScore, impactScore, attackVector, baseSeverity, attackComplexity. The parameters correspond to the role of CVSSV(3.0/3.1) metrification
  - [x] Information from the CISA database. The "cisa" tag is added provided that the CVE was found in the database.
  - [x] Information from the EPSS database. The tag "epss_(critical/high/medium/low)" is added.
  - [x] Information from the exploit-db database. The "exploit-db" tag is added, provided that the CVE was found in the database.

**Pool of possible tags:**

    1. {AccessVector} - av_n - meaning NETWORK; av_l - meaning LOCAL; av_a - meaning Adjacent; av_p - meaning Physical;
    2. {AttackComplexity} - ac_l - meaning Low; ac_h - meaning High;
    3. {BaseSeverity} - base_none; base_low; base_medium; base_high; base_critical;
    4. {ImpactScore} -  impact_none; impact_low; impact_medium; impact_high; impact_critical;
    5. {ExploitabilityScore} - exploitability_none; exploitability_low; exploitability_medium; exploitability_high; exploitability_critical;
    6. {Exploit-db} - exploit-db;
    7. {CISA} - cisa;
    8. {EPSS} - epss_low; epss_medium; epss_high; epss_critical;

# Framework configuration🔧

**The configuration is set in the .env file**

You need to add credentials to the main fields

* URL= < DefectDojo simple path to findings >
* Token= < DefectDojo API token >
* Web_Hook_Alert = < WEB Hook path to send alert message>
* Web_Hook_Debug = < WEB Hook path to send debug message about problems of framework work >
* NIST_API_KEY = < NIST API KEY >
* NIST_URL = https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=
* Cisa_URL = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
* EPSS_URL = https://api.first.org/data/v1/epss?cve=

## Functionality and stages of work:
When innumerating each finding, the framework does:
  
1. Checking flags and subflags for correct sampling and operation of the processing mode.
2. Finding CVEs in Finding. Search by the [vulnerability_ids] field if there is no CVE, search by the [title], [description], [references] fields using a regular expression.
3. Find CVE information in the NIST NVD and add tags.
4. Search the Exploit-db database for CVE information and add a tag.
5. Search for CVE information in the CISA database and add a tag.
6. Search for CVE information in the EPSS database and add a tag.
7. Updating tags in finding.
8. Write a message about a critical vulnerability to the "logs/alert_list" file when local conditions are met.

**After innumeration, the framework checks the condition for the presence of the {report} subflag and, if present, reads “logs/logfile.log” + collects general statistics and sends a message in some chat by WEBHOOK. Next, the file “logs/alert_list” is read and send message about critical vulnerabilities to channel in some chat by WEBHOOK**

## UML diagram of the framework's operation sequence

**The diagram code is specified in the app/uml/processes.puml file**

# Docker-image

1.  Build
    ```console
    docker build -t expdd .
    ```
2. Запуск образа "expdd"
    ```console
    docker run expdd
    ```
