sub vcl_recv {

    # Redirect all of these things to Warehouse, except for XML-RPC, which we will
    # simply change the backend so that it points to Warehouse.
    # TODO: We should probably move this redirect, as well as the XML-RPC handling
    #       into the Warehouse service so that we don't miss any important VCL
    #       changes, particularly for XML-RPC since this will short-circuit that
    #       logic. Unfortuantely we can't do that until after Legacy PyPI is dead
    #       because of the Artifactory exclusion.
    if (req.http.Host != "legacy.pypi.org" && !(req.http.User-Agent ~ "^Artifactory/")) {
        if (req.request == "POST" && (req.url ~ "^/pypi$" || req.url ~ "^/pypi/$") && req.http.Content-Type ~ "text/xml") {
            # Change the backend to Warehouse for XML-RPC.
            set req.http.Host = "test.pypi.org";
            set req.backend = F_test_pypi_org;
        } else {
            # Set our location to Warehouse.
            set req.http.Location = "https://test.pypi.org" req.url;

            # We want to use a 301/302 redirect for GET/HEAD, because that has the widest
            # support and is a permanent redirect. However it has the disadvantage of
            # changing a POST to a GET, so for POST, etc we will attempt to use a 308/307
            # redirect which will keep the method. 308/307 redirects are new and older
            # tools may not support them, so we may need to revisit this.
            if (req.request == "GET" || req.request == "HEAD") {
                error 750 "Moved Permanently";
            } else {
                error 752 "Permanent Redirect";
            }
        }
    }

    # Some (Older) clients will send a hash fragment as part of the URL even
    # though that is a local only modification. This breaks this badly for the
    # files in S3, and in general it's just not needed.
    set req.url = regsub(req.url, "#.*$", "");

    # Force SSL for GET and HEAD requests
    if (req.request == "GET" || req.request == "HEAD") {
        if (!req.http.Fastly-SSL) {
            # Don't silently upgrade /simple/ and /packages/ to HTTPS, force the clients to change
            if (req.url ~ "^/(simple|packages)") {
                error 803 "SSL is required";
            }

            error 801 "Force SSL";
        }
    }

    # We want to record the real URL early on.
    set req.http.RealURL = req.url;
    set req.http.RealURLPath = req.url.path;
    set req.http.RealHost = req.http.Host;

    # Currently Fastly does not provide a way to access response headers when
    # the response is a 304 response. This is because the RFC states that only
    # a limit set of headers should be sent with a 304 response, and the rest
    # are SHOULD NOT. Since this stripping happens *prior* to vcl_deliver being
    # ran, that breaks our ability to log on 304 responses. Ideally at some
    # point Fastly offers us a way to access the "real" response headers even
    # for a 304 response, but for now, we are going to remove the headers that
    # allow a conditional response to be made. If at some point Fastly does
    # allow this, then we can delete this code.
    if (!req.http.Fastly-FF
            && std.tolower(req.http.RealHost) == "files.pythonhosted.org"
            && req.url.path ~ "^/packages/[a-f0-9]{2}/[a-f0-9]{2}/[a-f0-9]{60}/") {
        unset req.http.If-None-Match;
        unset req.http.If-Modified-Since;
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

    # Certain pages should never be cached
    if (req.url ~ "^/(daytime|id|oauth)") {
        return (pass);
    }

    # Don't attempt to cache methods that are not cache safe
    if (req.request != "HEAD" && req.request != "GET" && req.request != "PURGE") {
      return(pass);
    }

    # Don't attempt to cache requests that include Authorization or Cookies
    # unless they are going to Amazon S3.
    if (!req.http.Host ~ ".s3.amazonaws.com$") {
        if (req.http.Authenticate || req.http.Authorization || req.http.Cookie) {
            return (pass);
        }
    }

    set req.http.X-ClientIDHash = digest.hash_md5(client.ip req.http.User-Agent);
    set req.http.X-ClientID = std.strtol(req.http.X-ClientIDHash,16);

    if (req.url ~ "^/simple/") {
        if (randombool_seeded(1,100,std.atoi(req.http.X-ClientID)) || req.http.Force-Warehouse-Redirect) {
            set req.http.Location = "https://test.pypi.org" req.url;
            error 751 "See Other";
        }
    }

    return(lookup);
}


sub vcl_fetch {
#FASTLY fetch

    # Set the maximum grace period on an object
    set beresp.grace = 24h;

    if (beresp.http.x-amz-meta-project || beresp.http.x-amz-meta-version || beresp.http.x-amz-meta-package-type) {
        # Stash these variables on the Request so that we can access them in
        # vcl_deliver even during a 304 response.
        set req.http.Fastly-amz-meta-project = beresp.http.x-amz-meta-project;
        set req.http.Fastly-amz-meta-version = beresp.http.x-amz-meta-version;
        set req.http.Fastly-amz-meta-package-type = beresp.http.x-amz-meta-package-type;
    }

    # We need to modify a few things if we're caching an Amazon AWS request.
    if (req.http.Host ~ ".s3.amazonaws.com$") {
        if (beresp.status == 200) {
           set beresp.http.Cache-Control = "max-age=31557600, public";
           set beresp.ttl = 31557600s;
        }
        elseif (beresp.status == 404) {
            set beresp.http.Cache-Control = "max-age=60, public";
            set beresp.ttl = 60s;
        }

        remove beresp.http.x-amz-id-2;
        remove beresp.http.x-amz-request-id;
        remove beresp.http.x-amz-version-id;
        remove beresp.http.x-amz-meta-s3cmd-attrs;

        return (deliver);
    }

    # Ensure that private pages have Cache-Control: private set on them.
    if (req.http.Authenticate || req.http.Authorization || req.http.Cookie) {
        remove beresp.http.Cache-Control;
        set beresp.http.Cache-Control = "private";
    }

    # Certain pages should never be cached
    if (req.url ~ "^/(daytime|id|oauth)") {
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


sub vcl_deliver {
#FASTLY deliver

    set resp.http.X-Frame-Options = "deny";
    set resp.http.X-XSS-Protection = "1; mode=block";
    set resp.http.X-Content-Type-Options = "nosniff";
    set resp.http.X-Permitted-Cross-Domain-Policies = "none";

    # Currently Fastly does not provide a way to access response headers when
    # the response is a 304 response. This is because the RFC states that only
    # a limit set of headers should be sent with a 304 response, and the rest
    # are SHOULD NOT. Since this stripping happens *prior* to vcl_deliver being
    # ran, that breaks our ability to log on 304 responses. Ideally at some
    # point Fastly offers us a way to access the "real" response headers even
    # for a 304 response, but for now, we are going to remove the headers that
    # allow a conditional response to be made. If at some point Fastly does
    # allow this, then we can delete this code, and also allow a 304 response
    # in the http_status_matches() check further down.
    if (!req.http.Fastly-FF
            && std.tolower(req.http.RealHost) == "files.pythonhosted.org"
            && req.url.path ~ "^/packages/[a-f0-9]{2}/[a-f0-9]{2}/[a-f0-9]{60}/") {
        unset resp.http.ETag;
        unset resp.http.Last-Modified;
    }

    # If we're not executing a shielding request, and the URL is one of our file
    # URLs, and it's a GET request, and the response is either a 200 or a 304
    # then we want to log an event stating that a download has taken place.
    # if (!req.http.Fastly-FF && req.http.RealURLPath ~ "^/packages/[a-f0-9]{2}/[a-f0-9]{2}/[a-f0-9]{60}/" && req.request == "GET" && http_status_matches(resp.status, "200")) {
    #     if (http_status_matches(resp.status, "200,304")) {
    #         log {"syslog "} req.service_id {" linehaul :: "} "2@" now "|" geoip.country_code "|" req.http.RealURLPath "|" tls.client.protocol "|" tls.client.cipher "|" resp.http.x-amz-meta-project "|" resp.http.x-amz-meta-version "|" resp.http.x-amz-meta-package-type "|" req.http.user-agent;
    #         log {"syslog "} req.service_id {" downloads :: "} "2@" now "|" geoip.country_code "|" req.http.RealURLPath "|" tls.client.protocol "|" tls.client.cipher "|" resp.http.x-amz-meta-project "|" resp.http.x-amz-meta-version "|" resp.http.x-amz-meta-package-type "|" req.http.user-agent;
    #     }
    # }

    return(deliver);
}


sub vcl_error {
#FASTLY error

    if (obj.status == 803) {
        set obj.status = 403;
        set obj.response = "SSL is required";
        set obj.http.Content-Type = "text/plain; charset=UTF-8";
        synthetic {"SSL is required."};
        return (deliver);
    } else if (obj.status == 808) {
        set obj.status = 403;
        set obj.response = obj.http.Error-Message;
        set obj.http.Content-Type = "text/plain; charset=UTF-8";
        synthetic obj.http.Error-Message;
        return (deliver);
    } else if (obj.status == 750) {
        set obj.status = 301;
        set obj.http.Location = req.http.Location;
        set obj.http.Content-Type = "text/html; charset=UTF-8";
        synthetic {"<html><head><title>301 Moved Permanently</title></head><body><center><h1>301 Moved Permanently</h1></center></body></html>"};
        return(deliver);
    }
    else if (obj.status == 751) {
        set obj.status = 302;
        set obj.http.Location = req.http.Location;
        set obj.http.Content-Type = "text/html; charset=UTF-8";
        synthetic {"<html><head><title>302 Found</title></head><body><center><h1>302 Found</h1></center></body></html>"};
        return(deliver);
    }
    else if (obj.status == 752) {
        set obj.status = 308;
        set obj.http.Location = req.http.Location;
        set obj.http.Content-Type = "text/html; charset=UTF-8";
        synthetic {"<html><head><title>308 Permanent Redirect</title></head><body><center><h1>308 Permanent Redirect</h1></center></body></html>"};
        return(deliver);
    }
    else if (obj.status == 753) {
        set obj.status = 307;
        set obj.http.Location = req.http.Location;
        set obj.http.Content-Type = "text/html; charset=UTF-8";
        synthetic {"<html><head><title>308 Temporary Redirect</title></head><body><center><h1>308 Temporary Redirect</h1></center></body></html>"};
        return(deliver);
    }
}
