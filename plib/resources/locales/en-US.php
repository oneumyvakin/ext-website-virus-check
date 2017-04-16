<?php
// Copyright 1999-2016. Parallels IP Holdings GmbH.
$messages = array(
    'tabReports' => 'Reports',
    'tabSettings' => 'Settings',
    'tabAbout' => 'About',
    'pageTitle' => 'VirusTotal Website Check',
    'virustotalEnabled' => 'Enable scanning',
    'virustotalPublicApiKey' => 'VirusTotal Public API key',
    'adminHomeWidgetEnabled' => 'Add a widget with scan notifications to Administrator\'s home page',
    'settingsWasSuccessfullySaved' => 'Settings successfully saved.',
    'settingsFormApiCheckError' => 'Failed check API key. HTTP response: %%http_code%% %%http_error%%',
    'settingsFormApiInvalid' => 'API key is invalid. HTTP response: %%http_code%% %%http_error%%',
    'apiKeyBecameInvalid' => 'Last API request has finished with HTTP error 403',
    'buttonStartScan' => 'Start',
    'buttonStopScan' => 'Stop',
    'buttonStartDesc' => 'Start Scanning for all domains',
    'buttonStartSelectedDesc' => 'Start Scanning for selected domains',
    'buttonStopDesc' => 'Stop Scanning',
    'buttonDisable' => 'Disable',
    'buttonDisableDesc' => 'Disable scanning for selected domains.',
    'buttonDisableSuccess' => 'Scanning for domains was successfully disabled.',
    'buttonEnable' => 'Enable',
    'buttonEnableDesc' => 'Enable scanning for selected domains.',
    'buttonEnableSuccess' => 'Scanning for domains was successfully enabled.',
    'infoStartSuccess' => 'Scanning started',
    'infoStopSuccess' => 'Scanning stopped',
    'scanTaskRunning' => 'Scanning sites for viruses:',
    'scanTaskDone' => 'Scanning of sites finished. <a href="#" onclick="window.location.reload();">Refresh page</a>',
    'errorScanAlreadyRunning' => 'Scanning is already running.',
    'scanningState' => 'State',
    'scanningEnabled' => 'Scanning Enabled',
    'scanningDisabled' => 'Scanning Disabled',
    'badReport' => 'Bad report',
    'domain' => 'Domain',
    'vulnerabilities' => 'Vulnerabilities',
    'domainVulnerabilitiesNotFound' => 'Vulnerabilities are not found',
    'domainVulnerabilitiesFound' => 'Vulnerabilities are found',
    'vulnerabilityReportPageTitle' => 'Domain Vulnerabilities %%domain_name%%',
    'vulnerabilityCve' => 'CVE',
    'vulnerabilityAdvisoryDate' => 'Advisory Date',
    'vulnerabilityAdvisoryUrl' => 'Advisory URL',
    'vulnerabilitySoftwareName' => 'Software Name',
    'vulnerabilitySoftwareVersion' => 'Software Version',
    'vulnerabilityPath' => 'Path',
    'vulnerabilityError' => 'Error occurred while processing this vulnerability',
    'vulnerabilityErrorSubmitIssue' => 'Please feel free to submit issue in extension repository on <a rel="noopener noreferrer" target="_blank" href="https://github.com/plesk/ext-website-virus-check">GitHub</a>',

    'scannerErrorEncodeDomainsJson' => 'Vulnerability Scanner has failed to encode JSON to %%path%%',
    'scannerErrorSearchVersion' => 'Vulnerability Scanner has failed to search software version: %%msg%%',

    'yes' => 'Yes',
    'no' => 'No',
    'unknown' => 'Unknown',
    'domainInactiveOrCantbeResolvedInHostingIp' => 'Domain is "Suspended", "Disabled" or can\'t be resolved in hosting IP address',
    'scanDate' => 'Last scan Date',
    'checkResult' => 'Home page scan result (Detection ratio)',
    'badUrlsAndSamples' => 'Bad URLs and samples',
    'reportLink' => 'Link to scan report',
    'virustotalReport' => 'Open',
    'apikey_help' => 'You can get a free API key after you register at <a rel="noopener noreferrer" target=\'_blank\' href=\'https://virustotal.com/\'>VirusTotal</a>',
    'virustotalPromoTitle' => 'VirusTotal Reports',
    'virustotalPromoButtonTitle' => 'More info',
    'scanningWasNotPerformedYet' => 'Scanning was not performed yet.',
    'youCanStartTaskAt' => 'You can start scheduled task for scanning now at <a href="/admin/scheduler/tasks-list">Scheduled Tasks</a>',
    'scanningWasNotPerformedYetForList' => 'Scanning was not performed yet',
    'scanningRequestIsSent' => 'Scanning request is sent',
    'httpError' => 'HTTP Error: %%message%%',
    'httpErrorFailedToConnectVirusTotalUnknownError' => 'Failed to connect VirusTotal API server with Unknown error',
    'totalDomains' => 'Domains scanned: ',
    'ofTotalDomains' => ' of all domains selected for scanning ',
    'totalReports' => 'Total "bad" domains: ',
    'lastScan' => 'last scanning performed on ',
    'about' => 'This extension uses the public API of <a rel="noopener noreferrer" target=\'_blank\' href=\'https://virustotal.com/\'>VirusTotal</a> to detect malicious scripts on your websites. API requests are executed using daily scheduled tasks at <a href="/admin/scheduler/tasks-list">Scheduled Tasks</a>',
    'feedback' => 'If you have any questions or concerns about this extension, please feel free to submit issue in extension repository on <a rel="noopener noreferrer" target="_blank" href="https://github.com/plesk/ext-website-virus-check">GitHub</a>',
    'faq' => 'FAQ',
    'question2' => '<p><b>Q: Why daily scheduled tasks take so long to execute?</b><br />A: Because of the limitations of the public API the extension sends the API requests at the speed of 3 domains per minute.</p>',
    'question3' => '<p><b>Q: Can I execute daily scheduled task several times in a one day?</b><br />A: Yes, you can.</p>',
    'emailNotificationEnabled' => 'Enable email notifications',
    'emailNotificationSubjectBadDomain' => 'VirusTotal.com reports "bad" domain %%domain%%',
    'emailNotificationBodyBadDomain' => 'VirusTotal.com reports domain %%domain%% as "bad" %%url%%',
    'emailNotificationBodyVulnerabilities' => 'Vulnerability Scanner has found issues on domain %%domain%%. Please check report at %%url%%',
);