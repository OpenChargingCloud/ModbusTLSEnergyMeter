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

using org.GraphDefined.Vanaheimr.CLI;

using cloud.charging.open.protocols.WWCP.Node.CommandLine;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.CommandLine
{

    /// <summary>
    /// The command line of a running energy meter.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The node's command line, with the meter's prompt: the commands every
    /// node has, syncNTS among them, and the console from the first prompt
    /// until 'quit', Ctrl+C or SIGTERM. Everything a command needs is
    /// reachable from here - the meter itself, and through it its
    /// configuration, its log and everything the JSON API can do. A command is
    /// a second way of asking for the same thing as the web interface - never
    /// an implementation of its own.
    /// </para>
    /// <para>
    /// Commands are not listed anywhere. The constructor asks Styx to walk this
    /// assembly as well for anything that implements ICLICommand and can be
    /// built from a MeterCLI, so a command of the meter's own is a new file in
    /// this folder and nothing else. The one this meter had, syncNTS, is the
    /// node's now: a copy of it here would be a second command answering to the
    /// same word, and Styx runs neither of two that match.
    /// </para>
    /// <para>
    /// The meter's own are showMeterValues, showConnections, readRegisters
    /// and writeRegisters. The last is the one thing here the web interface
    /// has no page for - any register, rather than the meter mode and the
    /// energy counters - and it asks what the web interface asks for those
    /// two: "meter:edit".
    /// </para>
    /// <para>
    /// Here, beside the meter, and not in the program that runs it: what a
    /// meter can be told is the meter's, and is told over SSH as well as at
    /// the console. The meter hands it to whoever signs in over SSH by itself
    /// (see ModbusTLSEnergyMeter.cs), so that a meter hosted by a test, a
    /// service or another program has the same commands as one run by
    /// ModbusTLSEnergyMeterCLI. A program with commands of its own derives from
    /// this one and sets WWCPNode.CommandLines anew.
    /// </para>
    /// </remarks>
    public class MeterCLI : NodeCLI
    {

        #region Properties

        /// <summary>
        /// The energy meter these commands are about.
        /// </summary>
        public ModbusTLSEnergyMeter Meter { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create the command line of the given energy meter.
        /// </summary>
        /// <param name="Meter">The running energy meter.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands. This one is searched either way.</param>
        public MeterCLI(ModbusTLSEnergyMeter  Meter,
                        params Assembly[]     AssembliesWithCLICommands)

            : base(Meter, AssembliesWithCLICommands)

        {

            this.Meter = Meter;

            RegisterCLIType(typeof(MeterCLI));

        }

        /// <summary>
        /// Create the command line of the given ModbusTLSEnergyMeter on the given terminal,
        /// for the given caller - a session over SSH.
        /// </summary>
        /// <param name="Meter">The running ModbusTLSEnergyMeter.</param>
        /// <param name="Terminal">What the command line is typed at and written on.</param>
        /// <param name="Caller">Who is typing at it.</param>
        /// <param name="AssembliesWithCLICommands">Further assemblies to search for commands. This one and the node's are searched either way.</param>
        public MeterCLI(ModbusTLSEnergyMeter  Meter,
                        ICLITerminal          Terminal,
                        CLICaller             Caller,
                        params Assembly[]     AssembliesWithCLICommands)

            : base(Meter, Terminal, Caller, AssembliesWithCLICommands)

        {

            this.Meter = Meter;

            RegisterCLIType(typeof(MeterCLI));

        }

        #endregion


        #region (protected override) GetPrompt()

        /// <summary>
        /// The meter's serial number, because a meter usually runs on a bench
        /// beside a charging station and a vehicle, and often beside a second
        /// meter - and a console should say which of them it is before it asks
        /// for a command.
        /// </summary>
        /// <remarks>
        /// The serial number rather than a fixed word, as the vehicle takes its
        /// name: it is what --serial or --name gave this meter, what SunSpec
        /// Common Model 1 reports and what --selftest prints as "serial", so
        /// the prompt says the same thing about this meter as everything else.
        /// </remarks>
        protected override String GetPrompt()

            => $"{Meter.SerialNumber}> ";

        #endregion

    }

}
