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

using System.Buffers.Binary;

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// Puts the session model behind the models of any SunSpec device: the
    /// device answers for its own registers, and the session model for the
    /// ones after them.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A wrapper and not a part of the device, because it is the same for
    /// every device: this meter's own simulation, or a real meter it stands in
    /// front of. Where the device's list of models ended, the session model
    /// begins, and the list ends after it - so that whoever walks the list from
    /// "SunS", as every SunSpec client does, finds it there.
    /// </para>
    /// <para>
    /// A backend for each connection, because the registers a command is given
    /// are each connection's own; the session itself, its state and its
    /// document are the meter's and the same for everybody.
    /// </para>
    /// </remarks>
    public sealed class SessionModelBackendFactory : IModbusBackendFactory
    {

        #region Properties

        /// <summary>The device's backends.</summary>
        public IModbusBackendFactory  Inner           { get; }

        /// <summary>Who begins and ends the sessions.</summary>
        public SessionSigner          Signer          { get; }

        /// <summary>Where the id of the session model is: where the device's list of models ended.</summary>
        public UInt16                 ModelAddress    { get; }

        /// <summary>The last register of the session model, before the end of the list.</summary>
        public UInt16                 LastAddress
            => (UInt16) (ModelAddress + 1 + SessionModel.Length);

        /// <summary>Where the list of models ends now.</summary>
        public UInt16                 EndAddress
            => (UInt16) (ModelAddress + 2 + SessionModel.Length);

        /// <summary>
        /// The registers of the session model that may be written: what a role
        /// that may write what is commanded may write.
        /// </summary>
        public IReadOnlySet<UInt16>   WritableAddresses { get; }

        /// <summary>Said when a command was done: by whom, and what it did.</summary>
        public Action<String>         OnDone          { get; }

        /// <summary>Said when a command was refused: by whom, and why.</summary>
        public Action<String>         OnRefused       { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Put the session model behind a device whose list of models ends at
        /// the given address.
        /// </summary>
        /// <param name="Inner">The device's backends.</param>
        /// <param name="Signer">Who begins and ends the sessions.</param>
        /// <param name="ModelAddress">Where the device's list of models ends: its 0xFFFF.</param>
        /// <param name="OnDone">Said when a command was done.</param>
        /// <param name="OnRefused">Said when a command was refused.</param>
        /// <exception cref="ArgumentException">When the model does not fit below the last register.</exception>
        public SessionModelBackendFactory(IModbusBackendFactory  Inner,
                                          SessionSigner          Signer,
                                          UInt16                 ModelAddress,
                                          Action<String>?        OnDone      = null,
                                          Action<String>?        OnRefused   = null)
        {

            if (ModelAddress + 2 + SessionModel.Length + 1 > UInt16.MaxValue)
                throw new ArgumentException($"The session model has {SessionModel.Length + 2} registers and the end of the list after it two more, " +
                                            $"which do not fit between {ModelAddress} and the last register.",
                                            nameof(ModelAddress));

            this.Inner              = Inner;
            this.Signer             = Signer;
            this.ModelAddress       = ModelAddress;
            this.OnDone             = OnDone    ?? (_ => { });
            this.OnRefused          = OnRefused ?? (_ => { });
            this.WritableAddresses  = SessionModel.WritableAddresses(ModelAddress).ToHashSet();

        }

        #endregion


        #region CreateAsync(ConnectionId, Role, CancellationToken)

        public async Task<IModbusBackend> CreateAsync(Int64              ConnectionId,
                                                      String?            Role,
                                                      CancellationToken  CancellationToken)

            => new SessionModelBackend(
                   await Inner.CreateAsync(ConnectionId, Role, CancellationToken),
                   this,
                   ConnectionId,
                   Role
               );

        #endregion

    }


    /// <summary>
    /// The session model, as one connection sees it.
    /// </summary>
    internal sealed class SessionModelBackend(IModbusBackend              Inner,
                                              SessionModelBackendFactory  Factory,
                                              Int64                       ConnectionId,
                                              String?                     Role) : IModbusBackend
    {

        #region Data

        /// <summary>
        /// Where the model is, and who begins and ends the sessions.
        /// </summary>
        private SessionModelBackendFactory  Model { get; } = Factory;

        /// <summary>
        /// What this connection wrote for its next command.
        /// </summary>
        private readonly UInt16[]     given      = new UInt16[SessionModel.Length];

        private SessionRefusalKind    error      = SessionRefusalKind.None;
        private String                errorText  = "";

        #endregion


        #region ProcessRequestAsync(UnitId, RequestPDU, CancellationToken)

        public async Task<Byte[]> ProcessRequestAsync(Byte                  UnitId,
                                                      ReadOnlyMemory<Byte>  RequestPDU,
                                                      CancellationToken     CancellationToken)
        {

            var pdu = RequestPDU.ToArray();

            if (pdu.Length < 5)
                return await Inner.ProcessRequestAsync(UnitId, RequestPDU, CancellationToken);

            var function = (ModbusFunctionCodes) pdu[0];
            var first    = BinaryPrimitives.ReadUInt16BigEndian(pdu.AsSpan(1, 2));

            switch (function)
            {

                case ModbusFunctionCodes.ReadHoldingRegisters:
                case ModbusFunctionCodes.ReadInputRegisters:
                    {

                        var count = BinaryPrimitives.ReadUInt16BigEndian(pdu.AsSpan(3, 2));
                        var last  = first + count - 1;

                        if (count is 0 or > 125)
                            return ModbusPDU.BuildException(function, ModbusExceptionCode.IllegalDataValue);

                        if (last < Model.ModelAddress || first > Model.EndAddress + 1)
                            return await Inner.ProcessRequestAsync(UnitId, RequestPDU, CancellationToken);

                        if (last > Model.EndAddress + 1)
                            return ModbusPDU.BuildException(function, ModbusExceptionCode.IllegalDataAddress);

                        var registers = new List<UInt16>(count);

                        // What lies before the model is the device's.
                        if (first < Model.ModelAddress)
                        {

                            var before = await Inner.ProcessRequestAsync(
                                                   UnitId,
                                                   ModbusPDU.BuildReadHoldingRegisters(first, (UInt16) (Model.ModelAddress - first)),
                                                   CancellationToken
                                               );

                            if (ModbusPDU.TryGetException(before) is ModbusExceptionCode code)
                                return ModbusPDU.BuildException(function, code);

                            registers.AddRange(ModbusPDU.DecodeReadResponse(before));

                        }

                        var view = new View(this);

                        for (var address = Math.Max(first, Model.ModelAddress); address <= last; address++)
                            registers.Add(view.At(address - Model.ModelAddress));

                        return ModbusPDU.BuildReadHoldingResponse([.. registers]);

                    }

                case ModbusFunctionCodes.WriteSingleRegister:
                    {

                        if (first < Model.ModelAddress || first > Model.EndAddress + 1)
                            return await Inner.ProcessRequestAsync(UnitId, RequestPDU, CancellationToken);

                        var value = BinaryPrimitives.ReadUInt16BigEndian(pdu.AsSpan(3, 2));

                        return await Write(function, first, [ value ]) ??
                               ModbusPDU.BuildWriteSingleRegisterResponse(first, value);

                    }

                case ModbusFunctionCodes.WriteMultipleRegisters:
                    {

                        var count = BinaryPrimitives.ReadUInt16BigEndian(pdu.AsSpan(3, 2));
                        var last  = first + count - 1;

                        if (last < Model.ModelAddress || first > Model.EndAddress + 1)
                            return await Inner.ProcessRequestAsync(UnitId, RequestPDU, CancellationToken);

                        if (pdu.Length < 6 || count is 0 or > 123 || pdu[5] != count * 2 || pdu.Length != 6 + count * 2)
                            return ModbusPDU.BuildException(function, ModbusExceptionCode.IllegalDataValue);

                        // Half the device's and half the model's is neither's.
                        if (first < Model.ModelAddress || last > Model.EndAddress + 1)
                            return ModbusPDU.BuildException(function, ModbusExceptionCode.IllegalDataAddress);

                        var values = new UInt16[count];

                        for (var i = 0; i < count; i++)
                            values[i] = BinaryPrimitives.ReadUInt16BigEndian(pdu.AsSpan(6 + 2 * i, 2));

                        return await Write(function, first, values) ??
                               ModbusPDU.BuildWriteMultipleRegistersResponse(first, count);

                    }

                default:
                    return await Inner.ProcessRequestAsync(UnitId, RequestPDU, CancellationToken);

            }

        }

        #endregion

        #region (private) Write(Function, First, Values)

        /// <summary>
        /// Write registers of the session model, and do the command when the
        /// command register is among them - or the exception saying why not.
        /// </summary>
        private async Task<Byte[]?> Write(ModbusFunctionCodes  Function,
                                          UInt16               First,
                                          UInt16[]             Values)
        {

            for (var i = 0; i < Values.Length; i++)
                if (!SessionModel.IsWritable(First + i - Model.ModelAddress - 2))
                    return ModbusPDU.BuildException(Function, ModbusExceptionCode.IllegalDataAddress);

            UInt16? command = null;

            for (var i = 0; i < Values.Length; i++)
            {

                var offset = First + i - Model.ModelAddress - 2;

                if (offset == SessionModel.Command)
                    command = Values[i];
                else
                    given[offset] = Values[i];

            }

            // Everything else is written first, so that one request can carry a
            // session's parameters and the command that begins it.
            if (command is not UInt16 what || what == (UInt16) SessionCommand.None)
                return null;

            var refusal = await Do(what);

            Array.Clear(given);

            error     = refusal?.Kind ?? SessionRefusalKind.None;
            errorText = refusal?.Why  ?? "";

            if (refusal is null)
                return null;

            Model.OnRefused($"{Who} was refused a {(what == (UInt16) SessionCommand.Start ? "start" : what == (UInt16) SessionCommand.Stop ? "stop" : $"command {what}")}: {refusal.Why}");

            return ModbusPDU.BuildException(
                       Function,
                       refusal.Kind is SessionRefusalKind.Unreadable or SessionRefusalKind.SigningFailed
                           ? ModbusExceptionCode.ServerDeviceFailure
                           : ModbusExceptionCode.IllegalDataValue
                   );

        }

        #endregion

        #region (private) Do(Command)

        private async Task<SessionRefusal?> Do(UInt16 Command)
        {

            switch ((SessionCommand) Command)
            {

                case SessionCommand.Start:
                    {

                        var texts = new Dictionary<String, String?>();

                        foreach (var (name, offset, length) in new[] {
                                     ("identification type",  SessionModel.IdentificationType,  SessionModel.IdentificationTypeLength),
                                     ("identification",       SessionModel.Identification,      SessionModel.IdentificationLength),
                                     ("charge point id type", SessionModel.ChargePointIdType,   SessionModel.ChargePointIdTypeLength),
                                     ("charge point id",      SessionModel.ChargePointId,       SessionModel.ChargePointIdLength),
                                     ("tariff text",          SessionModel.TariffText,          SessionModel.TariffTextLength),
                                     ("session id",           SessionModel.SessionId,           SessionModel.SessionIdLength)
                                 })
                        {

                            var text = SessionModel.Decode(given.AsSpan(offset, length));

                            if (text is null)
                                return new SessionRefusal(SessionRefusalKind.InvalidParameter, $"The {name} is not UTF-8.");

                            texts[name] = text;

                        }

                        var answer = await Model.Signer.Start(
                                               new SessionParameters(
                                                   texts["identification type"],
                                                   texts["identification"],
                                                   texts["charge point id type"],
                                                   texts["charge point id"],
                                                   texts["tariff text"],
                                                   texts["session id"]
                                               )
                                           );

                        if (answer.Value is StartedSession started)
                            Model.OnDone($"{Who} started the charging session '{started.Session.Id}'" +
                                         (started.Session.Parameters.StationSessionId is String id ? $" ('{id}')" : "") +
                                         $" at {started.Session.StartValue} kWh, to be signed with '{started.Key.Id}'.");

                        return answer.Refusal;

                    }

                case SessionCommand.Stop:
                    {

                        var sessionId = SessionModel.Decode(given.AsSpan(SessionModel.SessionId, SessionModel.SessionIdLength));

                        if (sessionId is null)
                            return new SessionRefusal(SessionRefusalKind.InvalidParameter, "The session id is not UTF-8.");

                        var answer = await Model.Signer.Stop(sessionId);

                        if (answer.Value is SignedSession signed)
                            Model.OnDone($"{Who} stopped the charging session '{signed.SessionId}'" +
                                         (signed.StationSessionId is String id ? $" ('{id}')" : "") +
                                         $": {signed.StartValue} kWh to {signed.StopValue} kWh, {signed.StopValue - signed.StartValue} kWh in all.");

                        return answer.Refusal;

                    }

                default:
                    return new SessionRefusal(SessionRefusalKind.UnknownCommand,
                                              $"{Command} is no command. 1 starts a session, 2 stops it.");

            }

        }

        #endregion

        #region (private) Who

        private String Who
            => $"Modbus/TLS connection {ConnectionId} ({Role ?? "no role"})";

        #endregion

        #region DisposeAsync()

        public ValueTask DisposeAsync()
            => Inner.DisposeAsync();

        #endregion


        #region (private) View

        /// <summary>
        /// The session model as one request reads it: everything taken once,
        /// so that a read does not see half of one session and half of the
        /// next.
        /// </summary>
        private sealed class View(SessionModelBackend Backend)
        {

            private readonly ChargingSession?  current    = Backend.Model.Signer.Sessions.Current;
            private readonly SignedSession?    last       = Backend.Model.Signer.Sessions.Last;

            private UInt16[]?                  errorText;
            private UInt16[]?                  sessionId;
            private (UInt16[] Registers, Int32 Bytes)? publicKey;
            private (UInt16[] Registers, Int32 Bytes)? document;

            /// <summary>
            /// The register at this offset from the model's id.
            /// </summary>
            public UInt16 At(Int32 Offset)
            {

                if (Offset == 0)                           return SessionModel.Id;
                if (Offset == 1)                           return SessionModel.Length;
                if (Offset == SessionModel.Length + 2)     return SunSpecChain.EndOfModels;
                if (Offset == SessionModel.Length + 3)     return 0;

                var point = Offset - 2;

                switch (point)
                {

                    case SessionModel.Command:  return 0;
                    case SessionModel.State:    return (UInt16) (current is not null ? SessionModelState.Running
                                                                    : last    is not null ? SessionModelState.Stopped
                                                                                          : SessionModelState.None);
                    case SessionModel.Error:    return (UInt16) Backend.error;
                    case SessionModel.Pad:      return 0;

                    case >= SessionModel.ErrorText and < SessionModel.ErrorText + SessionModel.ErrorTextLength:
                        errorText ??= Fitted(Backend.errorText, SessionModel.ErrorTextLength);
                        return errorText[point - SessionModel.ErrorText];

                    case >= SessionModel.CurrentSessionId and < SessionModel.CurrentSessionId + SessionModel.SessionIdLength:
                        sessionId ??= Fitted(current?.Parameters.StationSessionId ?? last?.StationSessionId, SessionModel.SessionIdLength);
                        return sessionId[point - SessionModel.CurrentSessionId];

                    case SessionModel.PublicKeyLength:
                        publicKey ??= Encoded(PublicKeyText(), SessionModel.PublicKeyRegisters);
                        return (UInt16) publicKey.Value.Bytes;

                    case >= SessionModel.PublicKey and < SessionModel.PublicKey + SessionModel.PublicKeyRegisters:
                        publicKey ??= Encoded(PublicKeyText(), SessionModel.PublicKeyRegisters);
                        return publicKey.Value.Registers[point - SessionModel.PublicKey];

                    case SessionModel.DocumentLength:
                        document ??= Encoded(current is null ? last?.Document : null, SessionModel.DocumentRegisters);
                        return (UInt16) document.Value.Bytes;

                    case >= SessionModel.Document and < SessionModel.Document + SessionModel.DocumentRegisters:
                        document ??= Encoded(current is null ? last?.Document : null, SessionModel.DocumentRegisters);
                        return document.Value.Registers[point - SessionModel.Document];

                    default:
                        // What this connection wrote for its next command.
                        return point >= 0 && point < SessionModel.Length
                                   ? Backend.given[point]
                                   : (UInt16) 0;

                }

            }

            /// <summary>
            /// The public key the running session will be signed with, or the
            /// one the last document was.
            /// </summary>
            private String? PublicKeyText()
            {

                if (current is not null)
                    return Backend.Model.Signer.Keys.Get(current.KeyId) is MeterKey key
                               ? MeterPublicKey.ForOCMF(key).Value
                               : null;

                return last?.PublicKey;

            }

            /// <summary>
            /// A text that has to fit, cut where it does not - a message, which
            /// loses its end rather than its meaning.
            /// </summary>
            private static UInt16[] Fitted(String?  Text,
                                           Int32    Registers)
            {

                var text = Text ?? "";

                while (System.Text.Encoding.UTF8.GetByteCount(text) > Registers * 2)
                    text = text[..^1];

                return SessionModel.Encode(text, Registers);

            }

            /// <summary>
            /// A text that has to be whole, or not there at all - a key or a
            /// document, which a cut makes into something else.
            /// </summary>
            private static (UInt16[] Registers, Int32 Bytes) Encoded(String?  Text,
                                                                     Int32    Registers)
            {

                var bytes = System.Text.Encoding.UTF8.GetByteCount(Text ?? "");

                return bytes <= Registers * 2
                           ? (SessionModel.Encode(Text, Registers), bytes)
                           : (new UInt16[Registers],                0);

            }

        }

        #endregion

    }

}
