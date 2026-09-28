// Runtime configuration, read from <meta> tags in index.html so that no
// inline script is needed (keeps the Content-Security-Policy strict). The
// {{placeholders}} in those tags are filled in by the C# server.

function meta(name: string): string | undefined {
    return document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`)?.content;
}

export const config = {

    /**
     * Where this web interface is mounted: "" on a port of its own, "/EV" or
     * the like when several of these programs share one HTTP server and are
     * told apart by the first path segment. See basePath.ts.
     */
    base:             meta('base')             ?? '',

    /** Everything about the meter itself.  */
    apiBase:          meta('api-base')         ?? '/api/v1',

    /**
     * Signing in and out, which is the node's HTTPExt API and not the meter's:
     * the meter knows what a role may do, the accounts know who somebody is.
     * Two doors because they answer two different questions.
     */
    extBase:          meta('ext-base')         ?? '/ext',

    frontendVersion:  meta('frontend-version') ?? '?',
    serverVersion:    meta('server-version')   ?? '?'

};
