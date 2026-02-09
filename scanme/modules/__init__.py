"""Scan modules registry."""

MODULES = {
    "netscan": "scanme.modules.netscan:NetScanner",
    "webscan": "scanme.modules.webscan:WebScanner",
    "dnsscan": "scanme.modules.dnsscan:DNSScanner",
    "recon": "scanme.modules.recon:ReconScanner",
    "wpscan": "scanme.modules.wpscan:WPScanner",
    "dirbust": "scanme.modules.dirbust:DirBuster",
    "cmsdetect": "scanme.modules.cmsdetect:CMSDetector",
}
