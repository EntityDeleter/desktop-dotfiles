// # Hardware Acceleration # //
user_pref("media.ffmpeg.vaapi.enabled", true);
user_pref("media.hardware-video-decoding.force-enabled", true);
user_pref("media.rdd-ffmpeg.enabled", true);
user_pref("media.av1.enabled", false);
user_pref("gfx.x11-egl.force-enabled", true);
user_pref("gfx.webrender.all", true);
user_pref("webgl.force-enabled", true);
user_pref("webgl.msaa-force", true);

user_pref("security.sandbox.content.read_path_whitelist", "/sys/");

// # Network # //
// user_pref("media.peerconnection.ice.default_address_only", true);
// user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
user_pref("media.peerconnection.ice.force_interface", "proton0");
user_pref("network.http.sendRefererHeader", 0);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.trr.mode", 5);
user_pref("network.dns.echconfig.enabled", true);
user_pref("network.dns.http3_echconfig.enabled", true);

// # Reporting # //
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);

// # Telemetry # //
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.server", "data:,");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);

// # Toolkit # //
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");

// # Ping # //
user_pref("browser.ping-centre.telemetry", false);
user_pref("beacon.enabled", false);

user_pref("app.shield.optoutstudies.enabled", false);

user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

// # Cache # //
// user_pref("browser.cache.disk.enable", false);
// user_pref("browser.cache.memory.enable", true);
// user_pref("browser.cache.memory.capacity", -1);
user_pref("browser.cache.disk.parent_directory", "/run/user/1000/firefox");

// # Tab Unloading # //
user_pref("browser.tabs.unloadOnLowMemory", true);
user_pref("browser.low_commit_space_threshold_percent", 100);
user_pref("browser.tabs.min_inactive_duration_before_unload", 300000);

// # Crash Reports # //
user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);

// # Forms # //
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);

user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

// # Downloads # //
user_pref("browser.download.useDownloadDir", false);
user_pref("browser.download.manager.addToRecentDocs", false);
user_pref("browser.download.alwaysOpenPanel", false);
user_pref("browser.download.start_downloads_in_tmp_dir", true);
user_pref("browser.download.always_ask_before_handling_new_types", true);

user_pref("browser.contentblocking.category", "strict");
user_pref("privacy.partition.serviceWorkers", true);
user_pref(
    "privacy.partition.always_partition_third_party_non_cookie_storage",
    true,
);
user_pref(
    "privacy.partition.always_partition_third_party_non_cookie_storage.exempt_sessionstorage",
    true,
);

// # Persistence # //
user_pref("network.cookie.lifetimePolicy", 2);
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", false);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.sitesettings", false);

user_pref("privacy.sanitize.timeSpan", 0);

user_pref("privacy.clearOnShutdown_v2.cache", true);
user_pref("privacy.clearOnShutdown_v2.historyFormDataAndDownloads", true);
user_pref("privacy.clearOnShutdown_v2.siteSettings", false);
user_pref("privacy.clearOnShutdown_v2.browsingHistoryAndDownloads", true);
user_pref("privacy.clearOnShutdown_v2.downloads", true);
user_pref("privacy.clearOnShutdown_v2.formdata", true);

user_pref("privacy.clearSiteData.cache", true);
user_pref("privacy.clearSiteData.historyFormDataAndDownloads", true);
user_pref("privacy.clearSiteData.cookiesAndStorage", false);
user_pref("privacy.clearSiteData.browsingHistoryAndDownloads", true);
user_pref("privacy.clearSiteData.formdata", true);

user_pref("privacy.clearHistory.cache", true);
user_pref("privacy.clearHistory.cookiesAndStorage", false);
user_pref("privacy.clearHistory.historyFormDataAndDownloads", true);
user_pref("privacy.clearHistory.siteSettings", false);
user_pref("privacy.clearHistory.browsingHistoryAndDownloads", true);
user_pref("privacy.clearHistory.formdata", true);

user_pref("places.history.enabled", false);

user_pref("privacy.resistFingerprinting", false);
defaultPref("privacy.resistFingerprinting.letterboxing", true);

// # Theme # //
user_pref("ui.systemUsesDarkTheme", true);

// # Addons # //
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("browser.discovery.enabled", false);
user_pref(
    "browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons",
    false,
);
user_pref(
    "browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features",
    false,
);

// # SafeBrowsing # //
user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);
user_pref("browser.safebrowsing.downloads.enabled", true);
user_pref("browser.safebrowsing.downloads.remote.enabled", true);
user_pref(
    "browser.safebrowsing.downloads.remote.block_potentially_unwanted",
    true,
);
defaultPref("browser.safebrowsing.blockedURIs.enabled", true);
defaultPref(
    "browser.safebrowsing.provider.google4.gethashURL",
    "https://safebrowsing.googleapis.com/v4/fullHashes:find?$ct=application/x-protobuf&key=%GOOGLE_SAFEBROWSING_API_KEY%&$httpMethod=POST",
);
defaultPref(
    "browser.safebrowsing.provider.google4.updateURL",
    "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?$ct=application/x-protobuf&key=%GOOGLE_SAFEBROWSING_API_KEY%&$httpMethod=POST",
);
defaultPref(
    "browser.safebrowsing.provider.google.gethashURL",
    "https://safebrowsing.google.com/safebrowsing/gethash?client=SAFEBROWSING_ID&appver=%MAJOR_VERSION%&pver=2.2",
);
defaultPref(
    "browser.safebrowsing.provider.google.updateURL",
    "https://safebrowsing.google.com/safebrowsing/downloads?client=SAFEBROWSING_ID&appver=%MAJOR_VERSION%&pver=2.2&key=%GOOGLE_SAFEBROWSING_API_KEY%",
);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon", true);

user_pref("network.proxy.failover_direct", true);

// # Search Bar # //
user_pref("browser.urlbar.trending.featureGate", false);
user_pref("browser.urlbar.addons.featureGate", false);
user_pref("browser.urlbar.amp.featureGate", false);
user_pref("browser.urlbar.fakespot.featureGate", false);
user_pref("browser.urlbar.mdn.featureGate", false);
user_pref("browser.urlbar.weather.featureGate", false);
user_pref("browser.urlbar.wikipedia.featureGate", false);
user_pref("browser.urlbar.yelp.featureGate", false);

user_pref("network.auth.subresource-http-auth-allow", 1);

// # Private Cache # //
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);
user_pref("media.memory_cache_max_size", 65536);
user_pref("browser.sessionstore.privacy_level", 2);

// # Negotiation # //
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.tls.enable_0rtt_data", false);
user_pref("security.OCSP.enabled", 1);
user_pref("security.OCSP.require", false);
user_pref("security.cert_pinning.enforcement_level", 2);
user_pref("security.remote_settings.crlite_filters.enabled", true);
user_pref("security.pki.crlite_mode", 2);

// # HTTPS # //
user_pref("security.mixed_content.block_display_content", true);
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_pbm", true);
user_pref("dom.security.https_only_mode_send_http_background_request", true);

user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("browser.xul.error_pages.expert_bad_cert", true);

user_pref("privacy.userContext.enabled", true);
user_pref("privacy.userContext.ui.enabled", true);

// # Misc # //
user_pref("browser.helperApps.deleteTempFileOnExit", true);
user_pref("browser.uitour.enabled", false);
user_pref("devtools.debugger.remote-enabled", false);
user_pref("permissions.default.shortcuts", 2);
user_pref("network.IDN_show_punycode", true);
user_pref("pdfjs.enableScripting", false);

user_pref("browser.contentanalysis.enabled", false);
user_pref("browser.contentanalysis.default_result", 0);
user_pref("privacy.antitracking.isolateContentScriptResources", true);

user_pref("security.csp.reporting.enabled", false);

user_pref("extensions.enabledScopes", 5);
user_pref("extensions.postDownloadThirdPartyPrompt", false);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);

user_pref("browser.contentblocking.category", "strict");
user_pref("privacy.fingerprintingProtection.pbmode", true);
user_pref("privacy.spoof_english", 2);

user_pref("widget.non-native-theme.use-theme-accent", false);

user_pref("browser.link.open_newwindow", 3);
user_pref("browser.link.open_newwindow.restriction", 0);

user_pref("signon.rememberSignons", false);

user_pref("keyword.enabled", false);

// # Necessities # //
user_pref("extensions.blocklist.enabled", true);
user_pref("network.http.referer.spoofSource", false);
user_pref("security.dialog_enable_delay", 1000);
user_pref("privacy.firstparty.isolate", false);
user_pref("extensions.webcompat.enable_shims", true);
user_pref("security.tls.version.enable-deprecated", false);
user_pref("extensions.webcompat-reporter.enabled", false);
user_pref("extensions.quarantinedDomains.enabled", true);

// # Headrs # //
user_pref("privacy.donottrackheader.enabled", true);
user_pref("privacy.globalprivacycontrol.enabled", true);
