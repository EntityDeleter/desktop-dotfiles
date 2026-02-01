user_pref("media.ffmpeg.vaapi.enabled", true);
user_pref("media.hardware-video-decoding.force-enabled", true);
user_pref("media.rdd-ffmpeg.enabled", true);
user_pref("media.av1.enabled", false);
user_pref("gfx.x11-egl.force-enabled", true);
user_pref("gfx.webrender.all", true);
user_pref("webgl.force-enabled", true);
user_pref("webgl.msaa-force", true);

user_pref("security.sandbox.content.read_path_whitelist", "/sys/");

// user_pref("media.peerconnection.ice.default_address_only", true);
// user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
user_pref("media.peerconnection.ice.force_interface", "proton0");
user_pref("network.http.sendRefererHeader", 0);
user_pref("network.captive-portal-service.enabled", false);
user_pref("network.trr.mode", 5);
user_pref("network.dns.echconfig.enabled", true);
user_pref("network.dns.http3_echconfig.enabled", true);

user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);

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

user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");

user_pref("browser.ping-centre.telemetry", false);
user_pref("beacon.enabled", false);

user_pref("app.shield.optoutstudies.enabled", false);

user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");

// user_pref("browser.cache.disk.enable", false);
// user_pref("browser.cache.memory.enable", true);
// user_pref("browser.cache.memory.capacity", -1);
user_pref("browser.cache.disk.parent_directory", "/run/user/1000/firefox");

user_pref("browser.tabs.unloadOnLowMemory", true);
user_pref("browser.low_commit_space_threshold_percent", 100);
user_pref("browser.tabs.min_inactive_duration_before_unload", 300000);

user_pref("breakpad.reportURL", "");
user_pref("browser.tabs.crashReporting.sendReport", false);
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);

user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);

user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

user_pref("browser.download.useDownloadDir", false);
user_pref("browser.download.manager.addToRecentDocs", false);

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

user_pref("privacy.resistFingerprinting", false);

user_pref("ui.systemUsesDarkTheme", true);

user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("browser.discovery.enabled", false);

user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);
user_pref("browser.safebrowsing.downloads.enabled", true);
user_pref("browser.safebrowsing.downloads.remote.enabled", true);
user_pref(
    "browser.safebrowsing.downloads.remote.block_potentially_unwanted",
    true,
);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon", true);

user_pref("network.proxy.failover_direct", true);

user_pref("browser.urlbar.trending.featureGate", false);
user_pref("browser.urlbar.addons.featureGate", false);
user_pref("browser.urlbar.amp.featureGate", false);
user_pref("browser.urlbar.fakespot.featureGate", false);
user_pref("browser.urlbar.mdn.featureGate", false);
user_pref("browser.urlbar.weather.featureGate", false);
user_pref("browser.urlbar.wikipedia.featureGate", false);
user_pref("browser.urlbar.yelp.featureGate", false);

user_pref("browser.formfill.enable", false);

user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);

user_pref("network.auth.subresource-http-auth-allow", 1);

user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);
user_pref("media.memory_cache_max_size", 65536);
user_pref("browser.sessionstore.privacy_level", 2);

user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.tls.enable_0rtt_data", false);
user_pref("security.OCSP.enabled", 1);
user_pref("security.OCSP.require", false);
user_pref("security.cert_pinning.enforcement_level", 2);
user_pref("security.remote_settings.crlite_filters.enabled", true);
user_pref("security.pki.crlite_mode", 2);

user_pref("security.mixed_content.block_display_content", true);
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_pbm", true);
user_pref("dom.security.https_only_mode_send_http_background_request", true);

user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("browser.xul.error_pages.expert_bad_cert", true);

user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

user_pref("privacy.userContext.enabled", true);
user_pref("privacy.userContext.ui.enabled", true);
