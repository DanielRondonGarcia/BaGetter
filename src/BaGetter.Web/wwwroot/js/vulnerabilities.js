/*
 * Vulnerability dashboard: lazy package-details loading (package summary page).
 *
 * The dashboard initially renders each hosted package as a collapsed summary
 * <details> group with no embedded version/finding markup. When a group is
 * expanded, this script fetches exactly that package's server-rendered details
 * fragment (/vulnerabilities?handler=PackageDetails&packageId=<ID>) and injects
 * it, showing a skeleton and aria-busy state meanwhile. Loads are deduplicated
 * per package (case-insensitively) for the lifetime of the current DOM page:
 * collapsing/reopening never causes a duplicate request. Failures stop loading
 * and show an explicit English error with a working Retry control — never
 * false clean content.
 *
 * The module is testable with Node built-ins: pass a root element (like
 * document) and dependency functions; a fake DOM with the same small surface
 * (addEventListener, open, get/setAttribute, querySelector, innerHTML) works.
 */
(function () {
    'use strict';

    var DETAILS_SELECTOR = 'details.vulnerability-package';
    var DETAILS_TARGET_SELECTOR = '[data-package-details]';
    var RETRY_ATTRIBUTE = 'data-vulnerability-retry';

    var SKELETON_HTML =
        '<div class="vulnerability-package-loading">' +
        '<div class="vulnerability-skeleton-line"></div>' +
        '<div class="vulnerability-skeleton-line vulnerability-skeleton-line-wide"></div>' +
        '<div class="vulnerability-skeleton-line vulnerability-skeleton-line-narrow"></div>' +
        '<p class="vulnerability-loading-text">Loading versions, please wait...</p>' +
        '</div>';

    function escapeHtml(value) {
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function errorHtml(packageId, reason) {
        return '<div class="vulnerability-package-error" role="alert">' +
            '<p>The package versions could not be loaded (' + escapeHtml(reason) + '). ' +
            'No version details are shown, so this is not a clean result; ' +
            'use "Retry" to try again.</p>' +
            '<button type="button" class="btn btn-default vulnerability-package-retry" ' +
            RETRY_ATTRIBUTE + '="' + escapeHtml(packageId) + '">Retry</button>' +
            '</div>';
    }

    function initVulnerabilityDashboard(root, dependencies) {
        if (!root || typeof root.querySelectorAll !== 'function') {
            return;
        }

        var fetchLike = (dependencies && dependencies.fetch) ||
            (typeof window !== 'undefined' ? window.fetch.bind(window) : null);
        var locationLike = (dependencies && dependencies.location) ||
            (typeof window !== 'undefined' ? window.location : { pathname: '/vulnerabilities' });
        if (typeof fetchLike !== 'function') {
            return;
        }

        // State map for the CURRENT DOM page (a page navigation reloads this
        // script): lowercase package ID -> 'loading' | 'loaded' | 'failed'.
        // It must be prototype-free: package IDs are arbitrary strings, and a
        // plain {} would inherit truthy constructor/__proto__ properties that
        // the dedupe check would misread as already-loaded state.
        var state = Object.create(null);
        var items = [];

        var detailsElements = root.querySelectorAll(DETAILS_SELECTOR);
        for (var index = 0; index < detailsElements.length; index++) {
            var details = detailsElements[index];
            var packageId = details.getAttribute && details.getAttribute('data-package-id');
            if (!packageId) {
                continue;
            }
            items.push({ key: packageId.toLowerCase(), packageId: packageId, details: details });
            // Native <details> 'toggle' events do not bubble, so each element
            // gets its own listener; a delegated container handler would never
            // observe toggles.
            (function (boundDetails) {
                boundDetails.addEventListener('toggle', function () {
                    handleToggle(boundDetails);
                });
            })(details);
        }

        function findById(key) {
            for (var index = 0; index < items.length; index++) {
                if (items[index].key === key) {
                    return items[index].details;
                }
            }
            return null;
        }

        function setAriaBusy(details, busy) {
            if (busy) {
                details.setAttribute('aria-busy', 'true');
            } else {
                details.removeAttribute('aria-busy');
            }
        }

        function buildDetailsUrl(packageId) {
            var base = locationLike && typeof locationLike.pathname === 'string'
                ? locationLike.pathname
                : '/vulnerabilities';
            return base + '?handler=PackageDetails&packageId=' + encodeURIComponent(packageId);
        }

        function load(details, key, packageId) {
            var target = details.querySelector && details.querySelector(DETAILS_TARGET_SELECTOR);
            if (!target) {
                return;
            }

            state[key] = 'loading';
            setAriaBusy(details, true);
            // The skeleton respects the theme's CSS variables and reduced motion.
            target.innerHTML = SKELETON_HTML;

            fetchLike(buildDetailsUrl(packageId), { credentials: 'same-origin' })
                .then(function (response) {
                    if (!response || !response.ok) {
                        throw new Error('HTTP ' + (response && response.status));
                    }
                    return response.text();
                })
                .then(function (html) {
                    state[key] = 'loaded';
                    setAriaBusy(details, false);
                    // Server-rendered, escaped fragment content; inserted as-is.
                    target.innerHTML = html;
                })
                .catch(function (error) {
                    state[key] = 'failed';
                    setAriaBusy(details, false);
                    var reason = error && typeof error.message === 'string' && error.message
                        ? error.message
                        : 'the request failed';
                    target.innerHTML = errorHtml(packageId, reason);
                });
        }

        function handleToggle(details) {
            if (!details.open) {
                // Collapsing never cancels or refetches anything.
                return;
            }

            var packageId = details.getAttribute && details.getAttribute('data-package-id');
            if (!packageId) {
                return;
            }

            var key = packageId.toLowerCase();
            // Deduplicate in-flight and completed loads; a failed load stops
            // loading (only its explicit Retry control refetches).
            if (state[key]) {
                return;
            }

            load(details, key, packageId);
        }

        // Retry: a plain button inside the error markup (click events bubble,
        // unlike toggle), delegated on the shared root.
        root.addEventListener('click', function (event) {
            var target = event && event.target;
            var packageId = target && target.getAttribute && target.getAttribute(RETRY_ATTRIBUTE);
            if (!packageId) {
                return;
            }

            var key = packageId.toLowerCase();
            delete state[key];
            var details = findById(key);
            if (details && details.open) {
                load(details, key, details.getAttribute('data-package-id'));
            }
        });
    }

    if (typeof window !== 'undefined' && typeof document !== 'undefined') {
        initVulnerabilityDashboard(document, {
            fetch: window.fetch.bind(window),
            location: window.location,
        });
    }

    if (typeof module !== 'undefined' && module.exports) {
        module.exports = { initVulnerabilityDashboard: initVulnerabilityDashboard };
    }
})();
