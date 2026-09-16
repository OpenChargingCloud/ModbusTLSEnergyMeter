/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of the Modbus/TLS Energy Meter <https://github.com/OpenChargingCloud/ModbusTLSEnergyMeter>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// The page a person opens: the bundle built from Frontend/, embedded in
    /// this assembly and served at "/".
    /// </summary>
    /// <remarks>
    /// The stylesheet is SCSS and the page is TypeScript, both bundled by
    /// webpack into Frontend/dist and embedded by the project file - the same
    /// arrangement an OpenChargingCloud charging station uses, so that the two
    /// web interfaces can share a shape without sharing a copy of it.
    ///
    /// Every URL that is not one of the APIs and does not look like a file of
    /// the bundle gets the stub with status 200, which is what makes a reload
    /// on a deep link and a bookmark to one work. A URL that does look like a
    /// file and is not one gets a real 404: a mistyped script tag must not
    /// hand the browser HTML to execute.
    ///
    /// Nothing is rendered here. The page signs in against the account API and
    /// reads everything else from the meter's JSON API, so there is one set of
    /// rules about who may see what, enforced in one place, whether the reader
    /// is a browser or curl.
    /// </remarks>
    public class MeterWebInterface : org.GraphDefined.Vanaheimr.Hermod.HTTP.HTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the bundle lives inside this assembly.
        /// </summary>
        public const String  ResourcePrefix  = "cloud.charging.open.EnergyMeters.ModbusTLS.HTTPRoot.";

        /// <summary>
        /// The stub within the bundle, served for every page URL.
        /// </summary>
        public const String  IndexFile       = "index.html";

        /// <summary>
        /// What a browser asks for whatever the page says.
        /// </summary>
        public const String  FaviconSVG      = "favicon.svg";

        #endregion

        #region Properties

        /// <summary>
        /// Where the files of the web interface come from.
        /// </summary>
        public IStaticContentSource  Frontend       { get; }

        /// <summary>
        /// Whether there is a web interface to serve at all. False for an
        /// assembly built without the bundle, and then the JSON API is all
        /// there is.
        /// </summary>
        public Boolean               IsAvailable    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Serve the web interface of a meter from its HTTP server.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server.</param>
        /// <param name="Version">The version of the meter, shown on the page.</param>
        /// <param name="Frontend">Where the files come from; the bundle embedded in this assembly by default.</param>
        /// <param name="RootPath">Where the page is served, "/" by default.</param>
        public MeterWebInterface(HTTPServer             HTTPServer,
                                 String                 Version,
                                 IStaticContentSource?  Frontend   = null,
                                 HTTPPath?              RootPath   = null)

            : base(HTTPServer,
                   RootPath:     RootPath ?? HTTPPath.Root,
                   Description:  I18NString.Create("The web interface of this energy meter"))

        {

            this.Frontend     = Frontend ?? new EmbeddedContentSource(
                                                ResourcePrefix,
                                                typeof(MeterWebInterface).Assembly
                                            );

            this.IsAvailable  = this.Frontend.TryGet(IndexFile, out _);

            if (!IsAvailable)
                return;

            this.MapSinglePageApplication(
                this.Frontend,
                new SinglePageAppOptions {
                    IndexFile       = IndexFile,
                    // The one thing the page cannot know by itself: which
                    // meter it was served by. Everything else it asks for.
                    IndexTransform  = html => html.Replace("{{ServerVersion}}", Version, StringComparison.Ordinal)
                }
            );

            // Browsers ask for /favicon.ico whatever the page says, and a
            // bundle built by webpack carries an SVG. A literal route wins over
            // the catch-all, so this answers before the stub would - and beats
            // a 404 on every visit, which is a line in the log and a broken
            // icon in the tab.
            if (this.Frontend.TryGet(FaviconSVG, out _))
                AddHandler(
                    HTTPPath.Parse("/favicon.ico"),
                    request => Task.FromResult(
                                   new HTTPResponse.Builder(request) {
                                       HTTPStatusCode  = HTTPStatusCode.TemporaryRedirect,
                                       Location        = Location.From(HTTPPath.Parse("/" + FaviconSVG)),
                                       CacheControl    = "public, max-age=3600"
                                   }.AsImmutable
                               ),
                    HTTPMethod.GET
                );

        }

        #endregion

    }

}
