// ===============================================
// FIREFOX USER PREFERENCES - WITH EXPLANATIONS
// ===============================================

// ================================================
// HARDWARE ACCELERATION
// ================================================

// Enable hardware video acceleration using VA-API (Video Acceleration API) on Linux
user_pref("media.ffmpeg.vaapi.enabled", true);

// Don't force hardware video decoding - let Firefox decide based on system capabilities
user_pref("media.hardware-video-decoding.force-enabled", false);

// Enable Remote Data Decoder (RDD) process for FFmpeg - improves security by isolating media decoding
user_pref("media.rdd-ffmpeg.enabled", true);

// Disable AV1 codec support - may improve compatibility with older systems
user_pref("media.av1.enabled", false);

// Force enable EGL (Embedded Graphics Library) on X11 for better graphics performance
user_pref("gfx.x11-egl.force-enabled", true);

// Enable WebRender for all rendering - modern GPU-accelerated rendering engine
user_pref("gfx.webrender.all", true);

// Force enable WebGL for 3D graphics in the browser
user_pref("webgl.force-enabled", true);

// Disable WebGL debug renderer info to reduce fingerprinting surface
user_pref("webgl.enable-debug-renderer-info", false);

// Force enable MSAA (Multi-Sample Anti-Aliasing) for WebGL for better graphics quality
user_pref("webgl.msaa-force", true);

// Allow sandbox to read /sys/ directory for hardware information access
user_pref("security.sandbox.content.read_path_whitelist", "/sys/");

// ================================================
// NETWORK & DNS
// ================================================

// Disable captive portal detection - prevents automatic network connectivity checks
user_pref("network.captive-portal-service.enabled", false);

// Set DNS over HTTPS mode to 5 (disabled) - use system DNS resolver
user_pref("network.trr.mode", 5);

// Enable Encrypted ClientHello (ECH) configuration for DNS
user_pref("network.dns.echconfig.enabled", true);

// Enable ECH configuration for HTTP/3 connections
user_pref("network.dns.http3_echconfig.enabled", true);

// Allow fallback to direct connection if proxy fails
user_pref("network.proxy.failover_direct", true);

// Allow HTTP authentication for subresources (1 = allow)
user_pref("network.auth.subresource-http-auth-allow", 1);

// Use proxy for DNS lookups when using SOCKS proxy - prevents DNS leaks
user_pref("network.proxy.socks_remote_dns", true);

// Disable automatic offline status management
user_pref("network.manage-offline-status", false);

// Prevent opening unsafe JAR file types
user_pref("network.jar.open-unsafe-types", false);

// Disable participation in Mozilla experiments
user_pref("network.allow-experiments", false);

// Block access to .onion domains (Tor) when not using Tor browser
user_pref("network.dns.blockDotOnion", true);

// Disable insecure NTLM v1 authentication
user_pref("network.negotiate-auth.allow-insecure-ntlm-v1", false);

// Set Mozilla geolocation service URL
user_pref(
    "geo.wifi.uri",
    "https://location.services.mozilla.com/v1/geolocate?key=%MOZILLA_API_KEY%"
);

// Don't spoof the referer header (false = normal behavior, true would be spoofing)
user_pref("network.http.referer.spoofSource", false);

// Force WebRTC through ProtonVPN interface - REQUIRES ProtonVPN to be connected
user_pref("media.peerconnection.ice.force_interface", "proton0");

// ================================================
// SECURITY & CERTIFICATES
// ================================================

// Require safe TLS negotiation - reject connections that don't support secure renegotiation
user_pref("security.ssl.require_safe_negotiation", true);

// Disable TLS 1.3 0-RTT (zero round-trip time) to prevent replay attacks
user_pref("security.tls.enable_0rtt_data", false);

// Enable OCSP (Online Certificate Status Protocol) for checking certificate revocation
user_pref("security.OCSP.enabled", 1);

// Set certificate pinning enforcement to strict mode (2 = enforce)
user_pref("security.cert_pinning.enforcement_level", 2);

// Enable CRLite filters from remote settings for certificate revocation
user_pref("security.remote_settings.crlite_filters.enabled", true);

// Set CRLite mode to 2 (enforce) for certificate revocation checking
user_pref("security.pki.crlite_mode", 2);

// Treat unsafe TLS negotiation as a broken connection
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);

// Add 1 second delay before showing security dialogs to prevent clickjacking
user_pref("security.dialog_enable_delay", 1000);

// Don't allow deprecated TLS versions (< 1.2)
user_pref("security.tls.version.enable-deprecated", false);

// Block active mixed content (HTTP content on HTTPS pages that can alter the page)
user_pref("security.mixed_content.block_active_content", true);

// Block display mixed content (HTTP images, videos on HTTPS pages)
user_pref("security.mixed_content.block_display_content", true);

// Enforce strict origin policy for file:// URIs
user_pref("security.fileuri.strict_origin_policy", true);

// Enable Content Security Policy (CSP)
user_pref("security.csp.enable", true);

// Enable experimental CSP features
user_pref("security.csp.experimentalEnabled", true);

// Disable CSP violation reporting to reduce network traffic
user_pref("security.csp.reporting.enabled", false);

// Enable Subresource Integrity (SRI) for verifying external resources
user_pref("security.sri.enable", true);

// Enable OCSP stapling for better performance and privacy
user_pref("security.ssl.enable_ocsp_stapling", true);

// Enable OCSP Must-Staple - require OCSP stapling from servers that support it
user_pref("security.ssl.enable_ocsp_must_staple", true);

// Disable TLS session identifiers to prevent session tracking
user_pref("security.ssl.disable_session_identifiers", true);

// Set SHA-1 enforcement level to 1 (allow for locally-added roots only)
user_pref("security.pki.sha1_enforcement_level", 1);

// Disable automatic SSL error reporting to Mozilla
user_pref("security.ssl.errorReporting.automatic", false);

// Enable post-quantum key exchange (Kyber) for future-proof encryption
user_pref("security.tls.enable_kyber", true);

// Require master password entry every time (2 = always)
user_pref("security.ask_for_password", 2);

// Set password lifetime to 1 minute before requiring re-entry
user_pref("security.password_lifetime", 1);

// Don't automatically enable enterprise roots when MITM is detected
user_pref("security.certerrors.mitm.auto_enable_enterprise_roots", false);

// Don't trust enterprise root certificates
user_pref("security.enterprise_roots.enabled", false);

// ================================================
// HTTPS & SSL
// ================================================

// Force HTTPS-only mode for all connections
user_pref("dom.security.https_only_mode", true);

// Force HTTPS-only mode in private browsing
user_pref("dom.security.https_only_mode_pbm", true);

// Send background HTTP request to check if site supports HTTPS
user_pref("dom.security.https_only_mode_send_http_background_request", true);

// Show expert options on certificate error pages
user_pref("browser.xul.error_pages.expert_bad_cert", true);

// Enable HSTS (HTTP Strict Transport Security) preload list
user_pref("network.stricttransportsecurity.preloadlist", true);

// Enable Encrypted Server Name Indication (ESNI)
user_pref("network.security.esni.enabled", true);

// Set SSL override behavior to 1 (show warning, allow override)
user_pref("browser.ssl_override_behavior", 1);

// Disable RSA with AES-128-GCM cipher (weak cipher)
user_pref("security.ssl3.rsa_aes_128_gcm_sha256", false);

// Disable RSA with AES-256-GCM cipher (weak cipher without forward secrecy)
user_pref("security.ssl3.rsa_aes_256_gcm_sha384", false);

// Enable ChaCha20-Poly1305 cipher with ECDHE-ECDSA (modern, fast cipher)
user_pref("security.ssl3.ecdhe_ecdsa_chacha20_poly1305_sha256", true);

// Enable ChaCha20-Poly1305 cipher with ECDHE-RSA (modern, fast cipher)
user_pref("security.ssl3.ecdhe_rsa_chacha20_poly1305_sha256", true);

// Disable DHE-RSA-Camellia256-SHA (vulnerable to logjam attack)
user_pref("security.ssl3.dhe_rsa_camellia_256_sha", false);

// Disable DHE-RSA-AES256-SHA (vulnerable to logjam attack)
user_pref("security.ssl3.dhe_rsa_aes_256_sha", false);

// Disable DHE-DSS-AES128-SHA (weak DSA key, max 1024 bits)
user_pref("security.ssl3.dhe_dss_aes_128_sha", false);

// Disable DHE-DSS-AES256-SHA (weak DSA key, max 1024 bits)
user_pref("security.ssl3.dhe_dss_aes_256_sha", false);

// Disable DHE-DSS-Camellia128-SHA (weak DSA key)
user_pref("security.ssl3.dhe_dss_camellia_128_sha", false);

// Disable DHE-DSS-Camellia256-SHA (weak DSA key)
user_pref("security.ssl3.dhe_dss_camellia_256_sha", false);

// Disable RSA-AES256-SHA (CBC cipher with SHA-1, vulnerable to attacks)
user_pref("security.ssl3.rsa_aes_256_sha", false);

// Disable RSA-AES128-SHA (CBC cipher with SHA-1, vulnerable to attacks)
user_pref("security.ssl3.rsa_aes_128_sha", false);

// Disable ECDHE-RSA-AES256-SHA (CBC cipher with SHA-1)
user_pref("security.ssl3.ecdhe_rsa_aes_256_sha", false);

// Disable ECDHE-ECDSA-AES256-SHA (CBC cipher with SHA-1)
user_pref("security.ssl3.ecdhe_ecdsa_aes_256_sha", false);

// ================================================
// PRIVACY - TRACKING PROTECTION
// ================================================

// Enable Enhanced Tracking Protection
user_pref("privacy.trackingprotection.enabled", true);

// Enable tracking protection in private browsing mode
user_pref("privacy.trackingprotection.pbmode.enabled", true);

// Set content blocking to strict mode
user_pref("browser.contentblocking.category", "strict");

// Enable fingerprinting protection in private browsing mode
user_pref("privacy.fingerprintingProtection.pbmode", true);

// Isolate content script resources to prevent tracking
user_pref("privacy.antitracking.isolateContentScriptResources", true);

// ================================================
// PRIVACY - COOKIES & STORAGE
// ================================================

// Cookie lifetime policy: 0 = accept normally
user_pref("network.cookie.lifetimePolicy", 0);

// Cookie behavior: 1 = block third-party cookies
user_pref("network.cookie.cookieBehavior", 1);

// Make third-party cookies session-only (deleted when browser closes)
user_pref("network.cookie.thirdparty.sessionOnly", true);

// Partition service workers by first-party domain to prevent cross-site tracking
user_pref("privacy.partition.serviceWorkers", true);

// Always partition third-party non-cookie storage (localStorage, etc.)
user_pref(
    "privacy.partition.always_partition_third_party_non_cookie_storage",
    true
);

// Exempt sessionStorage from partitioning for compatibility
user_pref(
    "privacy.partition.always_partition_third_party_non_cookie_storage.exempt_sessionstorage",
    true
);

// ================================================
// PRIVACY - DATA CLEARING
// ================================================

// Don't automatically sanitize data on shutdown (manual control)
user_pref("privacy.sanitize.sanitizeOnShutdown", false);

// Clear cache on shutdown
user_pref("privacy.clearOnShutdown.cache", true);

// Keep cookies on shutdown (don't delete)
user_pref("privacy.clearOnShutdown.cookies", false);

// Clear download history on shutdown
user_pref("privacy.clearOnShutdown.downloads", true);

// Clear form data on shutdown
user_pref("privacy.clearOnShutdown.formdata", true);

// Clear browsing history on shutdown
user_pref("privacy.clearOnShutdown.history", true);

// Clear offline app data on shutdown
user_pref("privacy.clearOnShutdown.offlineApps", true);

// Keep active sessions on shutdown
user_pref("privacy.clearOnShutdown.sessions", false);

// Keep site settings on shutdown
user_pref("privacy.clearOnShutdown.sitesettings", false);

// Time span for clearing data: 0 = everything
user_pref("privacy.sanitize.timeSpan", 0);

// Clear offline app data when using Clear Private Data
user_pref("privacy.cpd.offlineApps", true);

// Clear cache when using Clear Private Data
user_pref("privacy.cpd.cache", true);

// Keep cookies when using Clear Private Data
user_pref("privacy.cpd.cookies", false);

// Clear downloads when using Clear Private Data
user_pref("privacy.cpd.downloads", true);

// Clear form data when using Clear Private Data
user_pref("privacy.cpd.formdata", true);

// Clear history when using Clear Private Data
user_pref("privacy.cpd.history", true);

// Keep sessions when using Clear Private Data
user_pref("privacy.cpd.sessions", false);

// Version 2 preference: Clear cache on shutdown
user_pref("privacy.clearOnShutdown_v2.cache", true);

// Version 2 preference: Clear history, form data, and downloads on shutdown
user_pref("privacy.clearOnShutdown_v2.historyFormDataAndDownloads", true);

// Version 2 preference: Keep site settings on shutdown
user_pref("privacy.clearOnShutdown_v2.siteSettings", false);

// Version 2 preference: Clear browsing history and downloads on shutdown
user_pref("privacy.clearOnShutdown_v2.browsingHistoryAndDownloads", true);

// Version 2 preference: Clear downloads on shutdown
user_pref("privacy.clearOnShutdown_v2.downloads", true);

// Version 2 preference: Clear form data on shutdown
user_pref("privacy.clearOnShutdown_v2.formdata", true);

// Clear Site Data preference: Clear cache
user_pref("privacy.clearSiteData.cache", true);

// Clear Site Data preference: Clear history, form data, and downloads
user_pref("privacy.clearSiteData.historyFormDataAndDownloads", true);

// Clear Site Data preference: Keep cookies and storage
user_pref("privacy.clearSiteData.cookiesAndStorage", false);

// Clear Site Data preference: Clear browsing history and downloads
user_pref("privacy.clearSiteData.browsingHistoryAndDownloads", true);

// Clear Site Data preference: Clear form data
user_pref("privacy.clearSiteData.formdata", true);

// Clear History preference: Clear cache
user_pref("privacy.clearHistory.cache", true);

// Clear History preference: Keep cookies and storage
user_pref("privacy.clearHistory.cookiesAndStorage", false);

// Clear History preference: Clear history, form data, and downloads
user_pref("privacy.clearHistory.historyFormDataAndDownloads", true);

// Clear History preference: Keep site settings
user_pref("privacy.clearHistory.siteSettings", false);

// Clear History preference: Clear browsing history and downloads
user_pref("privacy.clearHistory.browsingHistoryAndDownloads", true);

// Clear History preference: Clear form data
user_pref("privacy.clearHistory.formdata", true);

// ================================================
// PRIVACY - HEADERS
// ================================================

// Send Do Not Track header with all requests
user_pref("privacy.donottrackheader.enabled", true);

// Send Global Privacy Control header with all requests
user_pref("privacy.globalprivacycontrol.enabled", true);

// Send referer header only on same-origin requests (1 = send only to same origin)
user_pref("network.http.sendRefererHeader", 1);

// ================================================
// PRIVACY - USER CONTEXT
// ================================================

// Enable container tabs (user contexts)
user_pref("privacy.userContext.enabled", true);

// Show container tabs UI in the browser
user_pref("privacy.userContext.ui.enabled", true);

// ================================================
// PRIVACY - FINGERPRINTING
// ================================================

// Disable fingerprinting resistance (can break some sites)
user_pref("privacy.resistFingerprinting", false);

// Disable letterboxing (adds margins to prevent fingerprinting via window size)
user_pref("privacy.resistFingerprinting.letterboxing", false);

// Block access to mozAddonManager when fingerprinting resistance is enabled
user_pref("privacy.resistFingerprinting.block_mozAddonManager", true);

// Spoof English language: 2 = spoof to en-US
user_pref("privacy.spoof_english", 2);

// Disable first party isolation (would break many sites if enabled)
user_pref("privacy.firstparty.isolate", false);

// ================================================
// TELEMETRY & REPORTING
// ================================================

// Disable data submission to Mozilla
user_pref("datareporting.policy.dataSubmissionEnabled", false);

// Disable Firefox Health Report uploads
user_pref("datareporting.healthreport.uploadEnabled", false);

// Disable usage statistics uploads
user_pref("datareporting.usage.uploadEnabled", false);

// Disable telemetry
user_pref("toolkit.telemetry.enabled", false);

// Disable unified telemetry
user_pref("toolkit.telemetry.unified", false);

// Set telemetry server to data: URL (effectively disables it)
user_pref("toolkit.telemetry.server", "data:,");

// Disable telemetry archiving
user_pref("toolkit.telemetry.archive.enabled", false);

// Disable new profile telemetry ping
user_pref("toolkit.telemetry.newProfilePing.enabled", false);

// Disable shutdown telemetry ping sender
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);

// Disable update telemetry ping
user_pref("toolkit.telemetry.updatePing.enabled", false);

// Disable Background Hang Reporter telemetry
user_pref("toolkit.telemetry.bhrPing.enabled", false);

// Disable first shutdown telemetry ping
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);

// Opt out of telemetry coverage
user_pref("toolkit.telemetry.coverage.opt-out", true);

// Opt out of code coverage
user_pref("toolkit.coverage.opt-out", true);

// Set coverage endpoint to empty (disables it)
user_pref("toolkit.coverage.endpoint.base", "");

// Disable activity stream telemetry feeds
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);

// Disable activity stream telemetry
user_pref("browser.newtabpage.activity-stream.telemetry", false);

// Disable ping centre telemetry
user_pref("browser.ping-centre.telemetry", false);

// Disable beacon API (used for analytics)
user_pref("beacon.enabled", false);

// ================================================
// CRASH REPORTS
// ================================================

// Set crash report URL to empty (disables crash reporting)
user_pref("breakpad.reportURL", "");

// Don't send crash reports for tabs
user_pref("browser.tabs.crashReporting.sendReport", false);

// Don't automatically submit unsubmitted crash reports
user_pref("browser.crashReports.unsubmittedCheck.autoSubmit2", false);

// Disable check for unsubmitted crash reports
user_pref("browser.crashReports.unsubmittedCheck.enabled", false);

// ================================================
// CACHE & MEMORY
// ================================================

// Set custom disk cache parent directory (tmpfs for better privacy/performance)
user_pref("browser.cache.disk.parent_directory", "/run/user/1000/firefox");

// Disable SSL disk cache (don't cache HTTPS content to disk)
user_pref("browser.cache.disk_cache_ssl", false);

// Disable disk cache
user_pref("browser.cache.disk.enable", true);

// Enable memory cache
user_pref("browser.cache.memory.enable", false);

// Disable offline cache
user_pref("browser.cache.offline.enable", false);

// Force media memory cache in private browsing
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);

// Set maximum media memory cache size to 64MB
user_pref("media.memory_cache_max_size", 65536);

// Session store privacy level: 2 = never store sensitive data
user_pref("browser.sessionstore.privacy_level", 2);

// ================================================
// TAB MANAGEMENT
// ================================================

// Unload tabs when system memory is low
user_pref("browser.tabs.unloadOnLowMemory", true);

// Set low memory threshold to 100% (always consider unloading inactive tabs)
user_pref("browser.low_commit_space_threshold_percent", 100);

// Minimum inactive duration before tab can be unloaded (5 minutes in milliseconds)
user_pref("browser.tabs.min_inactive_duration_before_unload", 300000);

// ================================================
// DOWNLOADS
// ================================================

// Always ask where to save downloads
user_pref("browser.download.useDownloadDir", false);

// Don't add downloads to recent documents (privacy)
user_pref("browser.download.manager.addToRecentDocs", false);

// Don't retain download history
user_pref("browser.download.manager.retention", 0);

// Don't always open download panel
user_pref("browser.download.alwaysOpenPanel", false);

// Start downloads in temp directory first
user_pref("browser.download.start_downloads_in_tmp_dir", true);

// Always ask before handling new file types
user_pref("browser.download.always_ask_before_handling_new_types", true);

// ================================================
// FORMS & AUTOFILL
// ================================================

// Don't remember login credentials
user_pref("signon.rememberSignons", false);

// Don't autofill login forms
user_pref("signon.autofillForms", false);

// Don't capture logins from forms without autocomplete attributes
user_pref("signon.formlessCapture.enabled", false);

// Don't autofill logins on HTTP sites
user_pref("signon.autofillForms.http", false);

// Don't store logins when autocomplete=off is set
user_pref("signon.storeWhenAutocompleteOff", false);

// Disable form history
user_pref("browser.formfill.enable", false);

// Set form data to expire immediately
user_pref("browser.formfill.expire_days", 0);

// Disable address autofill
user_pref("extensions.formautofill.addresses.enabled", false);

// Disable credit card autofill
user_pref("extensions.formautofill.creditCards.enabled", false);

// Show contextual warning for insecure form fields
user_pref("security.insecure_field_warning.contextual.enabled", true);

// Show UI warning for insecure passwords
user_pref("security.insecure_password.ui.enabled", true);

// ================================================
// EXTENSIONS & ADDONS
// ================================================

// Hide "Get Add-ons" pane
user_pref("extensions.getAddons.showPane", false);

// Disable addon recommendations in about:addons
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);

// Disable extension discovery pane
user_pref("browser.discovery.enabled", false);

// Disable addon recommendations (CFR)
user_pref(
    "browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons",
    false
);

// Disable feature recommendations (CFR)
user_pref(
    "browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features",
    false
);

// Disable all CFR (Contextual Feature Recommender)
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr", false);

// Set enabled extension scopes (5 = profile + application)
user_pref("extensions.enabledScopes", 5);

// Don't prompt after downloading third-party extensions
user_pref("extensions.postDownloadThirdPartyPrompt", false);

// Enable extension blocklist
user_pref("extensions.blocklist.enabled", true);

// Enable web compatibility shims for broken sites
user_pref("extensions.webcompat.enable_shims", true);

// Disable web compatibility reporter
user_pref("extensions.webcompat-reporter.enabled", false);

// Enable quarantine for potentially dangerous domains
user_pref("extensions.quarantinedDomains.enabled", true);

// Don't restrict extensions on Mozilla domains (empty = no restrictions)
user_pref("extensions.webextensions.restrictedDomains", "");

// Disable Shield recipe client (used for studies)
user_pref("extensions.shield-recipe-client.enabled", false);

// Enable extension updates
user_pref("extensions.update.enabled", true);

// Require extension signatures
user_pref("xpinstall.signatures.required", true);

// Set extension blocklist URL
user_pref(
    "extensions.blocklist.url",
    "https://blocklist.addons.mozilla.org/blocklist/3/%APP_ID%/%APP_VERSION%/"
);

// ================================================
// SAFE BROWSING
// ================================================

// Enable Safe Browsing
user_pref("browser.safebrowsing.enabled", true);

// Enable malware protection
user_pref("browser.safebrowsing.malware.enabled", true);

// Enable phishing protection
user_pref("browser.safebrowsing.phishing.enabled", true);

// Enable download protection
user_pref("browser.safebrowsing.downloads.enabled", true);

// Enable remote download checks
user_pref("browser.safebrowsing.downloads.remote.enabled", true);

// Block potentially unwanted downloads
user_pref(
    "browser.safebrowsing.downloads.remote.block_potentially_unwanted",
    true
);

// Enable blocked URI checking
user_pref("browser.safebrowsing.blockedURIs.enabled", true);

// Set Google Safe Browsing v4 hash URL
user_pref(
    "browser.safebrowsing.provider.google4.gethashURL",
    "https://safebrowsing.googleapis.com/v4/fullHashes:find?$ct=application/x-protobuf&key=%GOOGLE_SAFEBROWSING_API_KEY%&$httpMethod=POST"
);

// Set Google Safe Browsing v4 update URL
user_pref(
    "browser.safebrowsing.provider.google4.updateURL",
    "https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch?$ct=application/x-protobuf&key=%GOOGLE_SAFEBROWSING_API_KEY%&$httpMethod=POST"
);

// Set Google Safe Browsing v2 hash URL
user_pref(
    "browser.safebrowsing.provider.google.gethashURL",
    "https://safebrowsing.google.com/safebrowsing/gethash?client=SAFEBROWSING_ID&appver=%MAJOR_VERSION%&pver=2.2"
);

// Set Google Safe Browsing v2 update URL
user_pref(
    "browser.safebrowsing.provider.google.updateURL",
    "https://safebrowsing.google.com/safebrowsing/downloads?client=SAFEBROWSING_ID&appver=%MAJOR_VERSION%&pver=2.2&key=%GOOGLE_SAFEBROWSING_API_KEY%"
);

// Block uncommon downloads
user_pref("browser.safebrowsing.downloads.remote.block_uncommon", true);

// ================================================
// URL BAR & SEARCH
// ================================================

// Disable trending search suggestions in URL bar
user_pref("browser.urlbar.trending.featureGate", false);

// Disable addon suggestions in URL bar
user_pref("browser.urlbar.addons.featureGate", false);

// Disable AMP page suggestions in URL bar
user_pref("browser.urlbar.amp.featureGate", false);

// Disable Fakespot (review analysis) suggestions in URL bar
user_pref("browser.urlbar.fakespot.featureGate", false);

// Disable MDN documentation suggestions in URL bar
user_pref("browser.urlbar.mdn.featureGate", false);

// Disable weather suggestions in URL bar
user_pref("browser.urlbar.weather.featureGate", false);

// Disable Wikipedia suggestions in URL bar
user_pref("browser.urlbar.wikipedia.featureGate", false);

// Disable Yelp suggestions in URL bar
user_pref("browser.urlbar.yelp.featureGate", false);

// Don't trim URLs in address bar (show full URL including http://)
user_pref("browser.urlbar.trimURLs", false);

// Filter out javascript: URLs from address bar
user_pref("browser.urlbar.filter.javascript", true);

// Enable keyword search (use default search engine from address bar)
user_pref("keyword.enabled", true);

// ================================================
// SEARCH ENGINE
// ================================================

// Set search country code to US
user_pref("browser.search.countryCode", "US");

// Set search region to US
user_pref("browser.search.region", "US");

// Disable GeoIP-based search (don't detect location)
user_pref("browser.search.geoip.url", "");

// Disable geo-specific search defaults
user_pref("browser.search.geoSpecificDefaults", false);

// ================================================
// LOCALE & LANGUAGE
// ================================================

// Accept only US English language
user_pref("intl.accept_languages", "en-US, en");

// Don't match OS locale settings
user_pref("intl.locale.matchOS", false);

// Use US English locale for JavaScript
user_pref("javascript.use_us_english_locale", true);

// ================================================
// NEW TAB PAGE & POCKET
// ================================================

// Disable top stories section on new tab page
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);

// Don't show weather on new tab page
user_pref("browser.newtabpage.activity-stream.showWeather", false);

// Disable snippets on new tab page
user_pref("browser.newtabpage.activity-stream.feeds.snippets", false);

// Disable activity stream on new tab page
user_pref("browser.newtabpage.activity-stream.enabled", false);

// Disable enhanced new tab page
user_pref("browser.newtabpage.enhanced", false);

// Don't preload new tab page
user_pref("browser.newtab.preload", false);

// Set new tab directory ping to empty
user_pref("browser.newtabpage.directory.ping", "");

// Set new tab directory source to empty JSON
user_pref("browser.newtabpage.directory.source", "data:text/plain,{}");

// Disable Contile (sponsored tiles) on new tab page
user_pref("browser.topsites.contile.enabled", false);

// Disable top sites on new tab page
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);

// Don't show sponsored top sites
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);

// Disable Pocket integration
user_pref("browser.pocket.enabled", false);

// Disable Pocket extension
user_pref("extensions.pocket.enabled", false);

// ================================================
// MOZILLA SERVICES & STUDIES
// ================================================

// Opt out of Shield studies
user_pref("app.shield.optoutstudies.enabled", false);

// Disable Normandy recipe client (used for experiments)
user_pref("app.normandy.enabled", false);

// Set Normandy API URL to empty
user_pref("app.normandy.api_url", "");

// Don't support experiments
user_pref("experiments.supported", false);

// Disable experiments
user_pref("experiments.enabled", false);

// Set experiments manifest to empty
user_pref("experiments.manifest.uri", "");

// Disable VPN promotions
user_pref("browser.vpn_promo.enabled", false);

// Enable blocklist updates
user_pref("services.blocklist.update_enabled", true);

// Disable old Loop/Hello domains logging
user_pref("loop.logDomains", false);

// ================================================
// DEVELOPER TOOLS
// ================================================

// Disable remote debugging
user_pref("devtools.debugger.remote-enabled", false);

// Disable WebIDE (deprecated development tool)
user_pref("devtools.webide.enabled", false);

// Don't auto-install ADB Helper for WebIDE
user_pref("devtools.webide.autoinstallADBHelper", false);

// Don't auto-install FxDT Adapters for WebIDE
user_pref("devtools.webide.autoinstallFxdtAdapters", false);

// Disable chrome debugging
user_pref("devtools.chrome.enabled", false);

// Force local debugging only
user_pref("devtools.debugger.force-local", true);

// ================================================
// UI & THEME
// ================================================

// Use dark theme
user_pref("ui.systemUsesDarkTheme", true);

// Don't use theme accent colors
user_pref("widget.non-native-theme.use-theme-accent", false);

// Don't use document fonts (use system fonts for privacy/consistency)
user_pref("browser.display.use_document_fonts", 0);

// ================================================
// BROWSER BEHAVIOR
// ================================================

// Open links in new tab instead of new window (3 = new tab)
user_pref("browser.link.open_newwindow", 3);

// Don't restrict new window opening behavior
user_pref("browser.link.open_newwindow.restriction", 0);

// Delete temporary helper app files on exit
user_pref("browser.helperApps.deleteTempFileOnExit", true);

// Disable UI tour
user_pref("browser.uitour.enabled", false);

// Notify when offline apps request storage
user_pref("browser.offline-apps.notify", true);

// Don't create shortcut favicons
user_pref("browser.shell.shortcutFavicons", false);

// Default shortcuts permission: 1 = allow with site permission
user_pref("permissions.default.shortcuts", 1);

// Disable content analysis (enterprise DLP feature)
user_pref("browser.contentanalysis.enabled", false);

// Default content analysis result: 0 = deny
user_pref("browser.contentanalysis.default_result", 0);

// Hide usernames and passwords in URLs
user_pref("browser.fixup.hide_user_pass", true);

// Only send pings to same host
user_pref("browser.send_pings.require_same_host", true);

// Disable X11 clipboard autocopy
user_pref("clipboard.autocopy", false);

// Force usage of XDG desktop portals
user_pref("widget.use-xdg-desktop-portal.file-picker", 1);

// ================================================
// PLUGINS
// ================================================

// Disable Flash (0 = never activate)
user_pref("plugin.state.flash", 0);

// Disable crash reporter for Flash plugin
user_pref("dom.ipc.plugins.flash.subprocess.crashreporter.enabled", false);

// Set plugins to click-to-play
user_pref("plugins.click_to_play", true);

// ================================================
// PDF & MEDIA
// ================================================

// Disable JavaScript in PDFs
user_pref("pdfjs.enableScripting", false);

// Disable media video statistics
user_pref("media.video_stats.enabled", false);

// Disable Web Speech Recognition API
user_pref("media.webspeech.recognition.enable", false);

// Disable Web Speech Synthesis API
user_pref("media.webspeech.synth.enabled", false);

// ================================================
// BUILD IDENTIFIERS
// ================================================

// Spoof build ID to reduce fingerprinting
user_pref("general.buildID.override", "20100101");

// Spoof homepage override build ID
user_pref("browser.startup.homepage_override.buildID", "20100101");

// ================================================
// UPDATES
// ================================================

// Enable Firefox updates
user_pref("app.update.enabled", true);

// ================================================
// HISTORY
// ================================================

// Enable browsing history
user_pref("places.history.enabled", true);

// ================================================
// MISCELLANEOUS PRIVACY
// ================================================

// Disable WiFi geolocation logging
user_pref("geo.wifi.logging.enabled", false);

// Disable face detection in camera
user_pref("camera.control.face_detection.enabled", false);

// ================================================
// ⚠️ SETTINGS THAT MAY BREAK WEBSITES ⚠️
// ================================================

// REFERER POLICIES - May break authentication, payment processors, anti-CSRF
// Cross-origin referer policy: 2 = only send when host matches
user_pref("network.http.referer.XOriginPolicy", 2);

// Cross-origin referer trimming: 2 = trim to scheme, host, and port
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);

// Referer trimming policy: 2 = trim to scheme, host, and port
user_pref("network.http.referer.trimmingPolicy", 2);

// OCSP REQUIREMENT - May cause certificate errors and site loading failures
// Require OCSP response (fail if not available)
user_pref("security.OCSP.require", true);

// HARDWARE CONCURRENCY - May affect performance of web workers and multi-threaded apps
// Limit reported CPU cores to 2 (reduces fingerprinting, may impact performance on heavy sites)
user_pref("dom.maxHardwareConcurrency", 2);

// DEVICE SENSORS - Breaks sites that require motion sensors (games, AR, fitness apps)
user_pref("device.sensors.enabled", false);

// GAMEPAD API - Breaks browser-based games that use controllers
user_pref("dom.gamepad.enabled", false);

// WEBVR/WEBXR - Breaks virtual reality experiences
user_pref("dom.vr.enabled", false);

// ================================================
// ⚠️ MINOR COMPATIBILITY SETTINGS ⚠️
// (Rarely cause issues but included for completeness)
// ================================================

// Network Information API - Some sites check connection before loading heavy content
user_pref("dom.netinfo.enabled", false);

// Telephony API - Rarely used except in specific telecommunications apps
user_pref("dom.telephony.enabled", false);

// Vibration API - Used in some mobile games and notification systems
user_pref("dom.vibrator.enabled", false);

// FlyWeb API - Deprecated/experimental, almost nothing uses it
user_pref("dom.flyweb.enabled", false);

// IDN Punycode - Shows ASCII for international domains (cosmetic, not breaking)
user_pref("network.IDN_show_punycode", true);

