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

using System.Reflection;
using System.Text;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// The page a person opens: one HTML document, embedded in this assembly
    /// and served at "/".
    /// </summary>
    /// <remarks>
    /// One file, with its stylesheet and its script inside it, and no build
    /// step of its own. A meter is one screen's worth of things - what it is
    /// measuring, what it is configured as, and what has been asked of it -
    /// and a toolchain that has to be installed and kept working before that
    /// screen can be changed would cost more than it saves.
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
        /// Where the page lives inside this assembly.
        /// </summary>
        public const String  IndexResource  = "cloud.charging.open.EnergyMeters.ModbusTLS.HTTPRoot.index.html";

        private readonly Byte[]  index;
        private readonly String  eTag;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Serve the web interface of a meter from its HTTP server.
        /// </summary>
        /// <param name="HTTPServer">The HTTP server.</param>
        /// <param name="RootPath">Where the page is served, "/" by default.</param>
        public MeterWebInterface(HTTPServer  HTTPServer,
                                 HTTPPath?   RootPath   = null)

            : base(HTTPServer,
                   RootPath:     RootPath ?? HTTPPath.Root,
                   Description:  I18NString.Create("The web interface of this energy meter"))

        {

            index  = LoadIndex();

            // The hash of the page itself, and not the version of the assembly
            // carrying it: the version stays at 1.0.0 across every change made
            // while developing one, and a browser told the page had not changed
            // believes it. A page is its own identity.
            eTag   = $"\"{Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(index))[..16]}\"";

            AddHandler(HTTPPath.Root,                Index,    HTTPMethod.GET);
            AddHandler(HTTPPath.Root,                Index,    HTTPMethod.HEAD);
            AddHandler(HTTPPath.Root + "{path..}",   Index,    HTTPMethod.GET);

        }

        #endregion


        #region (private) Index(Request)

        /// <summary>
        /// The page, for "/" and for every path that is not one of the APIs.
        /// </summary>
        /// <remarks>
        /// The same document for every path rather than a 404, so that a reload
        /// on a deep link and a bookmark to one both work. Hermod dispatches to
        /// the most specific HTTPAPI first, so "/api" and the accounts are
        /// answered by their own APIs and never reach this.
        /// </remarks>
        private Task<HTTPResponse> Index(HTTPRequest Request)
        {

            if (Request.GetHeaderField("If-None-Match") == eTag)
                return Task.FromResult(
                           new HTTPResponse.Builder(Request) {
                               HTTPStatusCode  = HTTPStatusCode.NotModified,
                               ETag            = eTag,
                               CacheControl    = "no-cache"
                           }.AsImmutable
                       );

            return Task.FromResult(
                       new HTTPResponse.Builder(Request) {
                           HTTPStatusCode  = HTTPStatusCode.OK,
                           ContentType     = HTTPContentType.Text.HTML_UTF8,
                           Content         = index,
                           ETag            = eTag,

                           // Revalidated rather than cached blind: an operator
                           // who updates the meter should get the new page on
                           // the next reload, not when the browser feels like it.
                           CacheControl    = "no-cache"
                       }.AsImmutable
                   );

        }

        #endregion

        #region (private static) LoadIndex()

        /// <summary>
        /// The page out of this assembly, or a short one saying it is missing.
        /// </summary>
        /// <remarks>
        /// A meter whose web interface did not get embedded should still start
        /// and still serve Modbus - so this says what is wrong on the page
        /// itself rather than throwing, which would take the whole meter down
        /// over a build that forgot a resource.
        /// </remarks>
        private static Byte[] LoadIndex()
        {

            using var stream = typeof(MeterWebInterface).Assembly.GetManifestResourceStream(IndexResource);

            if (stream is null)
                return Encoding.UTF8.GetBytes(
                           "<!DOCTYPE html><meta charset=\"utf-8\"><title>Energy meter</title>" +
                           "<p>This meter was built without its web interface. " +
                           "The JSON API below <code>/api/v1</code> is unaffected."
                       );

            using var memory = new MemoryStream();
            stream.CopyTo(memory);

            return memory.ToArray();

        }

        #endregion

    }

}
