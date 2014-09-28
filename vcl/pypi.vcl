director pypi_backup_mirror random{
   {
    .backend = F_mirror_ord;
    .weight  = 100;
   }{
    .backend = F_mirror_syd;
    .weight  = 100;
   }
}

sub vcl_recv {
#FASTLY recv

    # Handle grace periods for where we will serve a stale response
    if (!req.backend.healthy) {
        # The backend is unhealthy which means we want to serve the stale
        #   response long enough (hopefully) for us to fix the problem.
        set req.grace = 24h;

        # The backend is unhealthy which means we want to serve responses as
        #   if the user was not logged in. This means they will be eligible
        #   for the cached pages.
        remove req.http.Authenticate;
        remove req.http.Authorization;
        remove req.http.Cookie;
    }
    else {
        # Avoid a request pileup by serving stale content if required.
        set req.grace = 15s;
    }

    # Normalize Accept-Encoding to either gzip, deflate, or nothing
    if (req.http.Accept-Encoding) {
        if (req.url ~ "\.(jpg|png|gif|gz|tgz|bz2|tbz|mp3|ogg)$") { #" # Fix a bug when highlighting this as Perl
            # No point in compressing these
            remove req.http.Accept-Encoding;
        }
        else if (req.http.Accept-Encoding ~ "gzip") {
            set req.http.Accept-Encoding = "gzip";
        }
        else if (req.http.Accept-Encoding ~ "deflate") {
            set req.http.Accept-Encoding = "deflate";
        }
        else {
            # unknown algorithm
            remove req.http.Accept-Encoding;
        }
    }

    # On a POST, we want to skip the shielding and hit backends directly.
    if (req.request == "POST") {
        set req.backend = autodirector_;
    }

    # Force SSL for GET and HEAD requests
    if (req.request == "GET" || req.request == "HEAD") {
        if (!req.http.Fastly-SSL) {
            error 801 "Force SSL";
        }
    }

    # Tell Varnish to use X-Forwarded-For, to set "real" IP addresses on all
    #   requests
    remove req.http.X-Forwarded-For;
    set req.http.X-Forwarded-For = req.http.Fastly-Client-IP;

    # Tell Varnish to use X-Forwarded-Proto to set the "real" protocol http
    #   or https.
    if (req.http.Fastly-SSL) {
        set req.http.X-Forwarded-Proto = "https";
    }
    else {
        set req.http.X-Forwarded-Proto = "http";
    }

    # Strip Cookies and Authentication headers from urls whose output will
    #   never be influenced by them.
    if (req.url ~ "^/(simple|packages|serversig|stats|local-stats|static|mirrors|security)") {
        remove req.http.Authenticate;
        remove req.http.Authorization;
        remove req.http.Cookie;
    }

    # Strip Cookies and Authentication headers from json urls
    if (req.url ~ "^/pypi/([^/]+|[^/]+/[^/]+)/json$") {
        remove req.http.Authenticate;
        remove req.http.Authorization;
        remove req.http.Cookie;
    }

    # Certain pages should never be cached
    if (req.url ~ "^/(daytime|serial|id|oauth)") {
        return (pass);
    }

    # Don't attempt to cache methods that are not cache safe
    if (req.request != "HEAD" && req.request != "GET" && req.request != "PURGE") {
      return(pass);
    }

    # Don't attempt to cache requests that include Authorization or Cookies
    if (req.http.Authenticate || req.http.Authorization || req.http.Cookie) {
        return (pass);
    }

    return(lookup);
}


sub vcl_fetch {
#FASTLY fetch

    # Set the maximum grace period on an object
    set beresp.grace = 24h;

    # Ensure that private pages have Cache-Control: private set on them.
    if (req.http.Authenticate || req.http.Authorization || req.http.Cookie) {
        remove beresp.http.Cache-Control;
        set beresp.http.Cache-Control = "private";
    }

    # Certain pages should never be cached
    if (req.url ~ "^/(daytime|serial|id|oauth)") {
        remove beresp.http.Cache-Control;
        set beresp.http.Cache-Control = "no-cache";
    }

    # Don't store anything that issues a Set-Cookie header
    if (beresp.http.Set-Cookie) {
        set req.http.Fastly-Cachetype = "SETCOOKIE";
        return (pass);
    }

    # Don't store anything that has Cache-Control: private
    if (beresp.http.Cache-Control ~ "private") {
        set req.http.Fastly-Cachetype = "PRIVATE";
        return (pass);
    }

    # Don't store anything that has Cache-Control: no-cache
    if (beresp.http.Cache-Control ~ "no-cache") {
        set req.http.Fastly-Cachetype = "NOCACHE";
        return (pass);
    }

    # If the response is a 404 work around the lack of headers in the response
    #   which prevents us from using Surrogate-Key based purging.
    if (beresp.status == 404) {
        set beresp.ttl = 60s;
        return (deliver);
    }

    # Apply a default TTL if there is not one set in the headers.
    if (beresp.http.Expires || beresp.http.Surrogate-Control ~ "max-age" || beresp.http.Cache-Control ~"(s-maxage|max-age)") {
        # keep the ttl here
    }
    else {
        # apply the default ttl
        set beresp.ttl = 60s;
    }

    return(deliver);
}
