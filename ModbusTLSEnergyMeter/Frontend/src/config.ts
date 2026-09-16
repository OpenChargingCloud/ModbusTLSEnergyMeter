// Runtime configuration, read from <meta> tags in index.html so that no
// inline script is needed (keeps the Content-Security-Policy strict). The
// {{placeholders}} in those tags are filled in by the C# server.

function meta(name: string): string | undefined {
    return document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`)?.content;
}

export const config = {

    /** Everything about the meter itself.  */
    apiBase:          meta('api-base')         ?? '/api/v1',

    /**
     * Signing in and out, which is Hermod's own account API and not the
     * meter's: the meter knows what a role may do, the accounts know who
     * somebody is. Two doors because they answer two different questions.
     */
    accountsBase:     meta('accounts-base')    ?? '/accounts',

    frontendVersion:  meta('frontend-version') ?? '?',
    serverVersion:    meta('server-version')   ?? '?'

};
