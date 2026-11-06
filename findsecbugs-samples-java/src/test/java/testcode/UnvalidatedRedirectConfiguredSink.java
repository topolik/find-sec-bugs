package testcode;

import javax.servlet.http.HttpServletRequest;

/**
 * redirectTo is a redirect sink only through the injection-sinks/unvalidated-redirect.txt
 * test resource, like a tag attribute setter that ends in a redirect.
 */
public class UnvalidatedRedirectConfiguredSink {

    public void redirectTo(String url) {
    }

    public void unvalidatedRedirect(HttpServletRequest req) {
        redirectTo(req.getParameter("url"));
    }

    public void safeRedirect() {
        redirectTo("/home");
    }
}
