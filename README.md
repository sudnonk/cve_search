# cve_search_by_version
Find CVEs from list of packages.

## Example 
When you only have list of package as a txt file like below, 

```rpm_qa.txt
mongodb-org-3.6.8-1.el7.x86_64
firewalld-0.4.4.4-15.el7_5.noarch
kexec-tools-2.0.15-13.el7_5.2.x86_64
libproxy-python-0.3.0-4.el6_3.x86_64
```

and want to find vulnerabilities  of those packages, execute

```
cve_search -f rpm_qa.txt 
```

then you can get list of CVEs in JSON format.


```JSON
{
  "packages": {
    "pack_name": "libproxy-python",
    "pack_version": "0.3.0",
    "pack_release": "4.el6_3",
    "pack_arch": "x86_64"
  },
  "cves": {
    "CVE-2013-0775": {
      "cve_id": "CVE-2013-0775",
      "cvss_2_base_score": 10,
      "cvss_2_severity": "HIGH",
      "cvss_3_base_score": 0,
      "cvss_3_base_severity": ""
    },
    "CVE-2013-0780": {
      "cve_id": "CVE-2013-0780",
      "cvss_2_base_score": 9.3,
      "cvss_2_severity": "HIGH",
      "cvss_3_base_score": 0,
      "cvss_3_base_severity": ""
    },
    "CVE-2013-0782": {
      "cve_id": "CVE-2013-0782",
      "cvss_2_base_score": 10,
      "cvss_2_severity": "HIGH",
      "cvss_3_base_score": 0,
      "cvss_3_base_severity": ""
    },
    "CVE-2013-0783": {
      "cve_id": "CVE-2013-0783",
      "cvss_2_base_score": 10,
      "cvss_2_severity": "HIGH",
      "cvss_3_base_score": 0,
      "cvss_3_base_severity": ""
    }
  }
},
{},{}...
```

## Install
