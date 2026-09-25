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

using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.Logging;

using MSLogging = Microsoft.Extensions.Logging;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Logging
{

    /// <summary>
    /// Hands Hermod an <see cref="MSLogging.ILogger"/> that writes into this
    /// meter's event log - the node's.
    /// </summary>
    /// <remarks>
    /// Hermod's own parts - the HTTP server, the Modbus/TLS frontend - say what
    /// they are doing through ILogger and know nothing of an event log. Without
    /// this they would write to a second place, and a meter with two logs has
    /// none: the console would hold half the story and the browser the other
    /// half, with no way to read them in order.
    /// </remarks>
    public sealed class EventLogLoggerFactory : MSLogging.ILoggerFactory
    {

        private readonly EventLog log;

        /// <summary>
        /// Create a factory writing into the given event log.
        /// </summary>
        public EventLogLoggerFactory(EventLog Log)
        {
            this.log = Log;
        }

        public MSLogging.ILogger CreateLogger(String CategoryName)
            => new EventLogLogger(log, TagOf(CategoryName));

        public void AddProvider(MSLogging.ILoggerProvider Provider)
        { }

        public void Dispose()
        { }


        #region (private static) TagOf(CategoryName)

        /// <summary>
        /// The tag an entry from this category gets, so that a reader can
        /// filter by what it is about rather than by which class wrote it.
        /// </summary>
        /// <remarks>
        /// A category is the full name of a type, which is the one part of a
        /// log line that somebody reading a meter's log already knows and
        /// cannot act on. What they want is "show me the Modbus".
        /// </remarks>
        private static String TagOf(String CategoryName)
        {

            // The meter's own type is called ModbusTLSEnergyMeter, so it
            // matches both of the first two tests - and it is the meter
            // talking, not the Modbus frontend. Most specific first.
            if (CategoryName.Contains("EnergyMeter",  StringComparison.OrdinalIgnoreCase))  return "meter";
            if (CategoryName.Contains("Modbus",       StringComparison.OrdinalIgnoreCase))  return "modbus";
            if (CategoryName.Contains("HTTP",         StringComparison.OrdinalIgnoreCase))  return "http";
            if (CategoryName.Contains("DNS",          StringComparison.OrdinalIgnoreCase))  return "dns";
            if (CategoryName.Contains("NTS",          StringComparison.OrdinalIgnoreCase))  return "nts";

            return "hermod";

        }

        #endregion

    }


    /// <summary>
    /// One category's worth of that.
    /// </summary>
    public sealed class EventLogLogger : MSLogging.ILogger
    {

        private readonly EventLog  log;
        private readonly String    tag;

        public EventLogLogger(EventLog  Log,
                              String    Tag)
        {
            this.log  = Log;
            this.tag  = Tag;
        }


        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull

            => null;


        public Boolean IsEnabled(MSLogging.LogLevel Level)

            // Everything is kept. What reaches a console or a browser is
            // decided where it is read, not here - an entry thrown away at this
            // point is one nobody can ask for afterwards.
            => Level != MSLogging.LogLevel.None;


        public void Log<TState>(MSLogging.LogLevel                Level,
                                MSLogging.EventId                 EventId,
                                TState                            State,
                                Exception?                        Exception,
                                Func<TState, Exception?, String>  Formatter)
        {

            var message = Formatter(State, Exception);

            if (message.Length == 0 && Exception is null)
                return;

            // Not EventLog.Exception, which would make every one of these an
            // error: Hermod reports a dropped connection as a warning with the
            // IOException attached, and that is a warning.
            if (Exception is not null)
                log.Log(
                    LevelOf(Level),
                    $"{message}: {Exception.Message}",
                    new JObject(
                        new JProperty("exception",   Exception.GetType().FullName),
                        new JProperty("message",     Exception.Message),
                        new JProperty("stackTrace",  Exception.StackTrace)
                    ),
                    tag
                );

            else
                log.Log(LevelOf(Level), message, tag);

        }


        #region (private static) LevelOf(Level)

        /// <summary>
        /// Microsoft's six levels onto ours.
        /// </summary>
        /// <remarks>
        /// Information becomes Info rather than Notice: Hermod writes a great
        /// deal at Information, and a log where everything is worth finding
        /// again has nothing that is.
        /// </remarks>
        private static LogLevel LevelOf(MSLogging.LogLevel Level)

            => Level switch {
                   MSLogging.LogLevel.Trace        => LogLevel.Debug,
                   MSLogging.LogLevel.Debug        => LogLevel.Debug,
                   MSLogging.LogLevel.Information  => LogLevel.Info,
                   MSLogging.LogLevel.Warning      => LogLevel.Warning,
                   MSLogging.LogLevel.Error        => LogLevel.Error,
                   MSLogging.LogLevel.Critical     => LogLevel.Critical,
                   _                               => LogLevel.Info
               };

        #endregion

    }

}
